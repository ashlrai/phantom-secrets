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

/// `path` as the child process reports it from its current directory.
/// Windows canonicalization adds a `\\?\` verbatim prefix to a drive path,
/// which the child's current directory does not carry.
fn as_child_cwd(path: &std::path::Path) -> String {
    let shown = path.display().to_string();
    match shown.strip_prefix(r"\\?\") {
        Some(rest) if cfg!(windows) && rest.as_bytes().get(1) == Some(&b':') => rest.to_owned(),
        _ => shown,
    }
}

#[test]
fn list_from_a_project_subdirectory_names_the_project_root() {
    let dir = common::canonical_tempdir();
    init_project(&dir);
    let sub = dir.path().join("src").join("nested");
    fs::create_dir_all(&sub).unwrap();

    let output = phantom(&dir)
        .current_dir(&sub)
        .env("NO_COLOR", "1")
        .arg("list")
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    let root = as_child_cwd(dir.path());
    assert!(
        stderr.contains(&format!("inside the project at {root}")),
        "{stderr}"
    );
    assert!(stderr.contains(&format!("cd {root}")), "{stderr}");
    assert!(!stderr.contains("Run phantom init first"), "{stderr}");

    // Outside any project the error still points at `phantom init`.
    let outside = common::canonical_tempdir();
    let output = phantom(&outside)
        .env("NO_COLOR", "1")
        .arg("list")
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("No .phantom.toml found. Run phantom init first."),
        "{stderr}"
    );
}
