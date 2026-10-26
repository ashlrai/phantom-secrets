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

#[test]
fn list_scope_is_exact_value_blind_and_preserves_project_state() {
    use phantom_vault::VaultBackend;

    let dir = common::canonical_tempdir();
    init_project(&dir);
    let config =
        phantom_core::config::PhantomConfig::load(&dir.path().join(".phantom.toml")).unwrap();
    fn encrypted_file(root: &std::path::Path) -> std::path::PathBuf {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                let found = encrypted_file(&path);
                if !found.as_os_str().is_empty() {
                    return found;
                }
            } else if path.extension().is_some_and(|ext| ext == "vault") {
                return path;
            }
        }
        std::path::PathBuf::new()
    }
    let encrypted = encrypted_file(dir.path());
    assert!(encrypted.is_file());
    let vault = phantom_vault::file::FileVault::new(
        encrypted.parent().unwrap().parent().unwrap(),
        config.local_project_id(),
        VAULT_PASS.to_string(),
    )
    .unwrap();
    let fixture_value = "scope-test-private-fixture";
    for name in [
        "dev/DEV_ONLY",
        "staging/STAGING_ONLY",
        "prod/PROD_ONLY",
        "development/OTHER",
        "default/CANONICAL",
        "LEGACY",
    ] {
        vault.store(name, fixture_value).unwrap();
    }
    fs::create_dir_all(dir.path().join(".phantom")).unwrap();
    let selector = dir.path().join(".phantom/env");
    fs::write(&selector, "staging\n").unwrap();
    let before = fs::read(&encrypted).unwrap();
    let config_before = fs::read(dir.path().join(".phantom.toml")).unwrap();
    let dotenv_before = fs::read(dir.path().join(".env")).unwrap();
    for (scope, expected) in [
        ("dev", vec!["dev/DEV_ONLY"]),
        ("staging", vec!["staging/STAGING_ONLY"]),
        ("prod", vec!["prod/PROD_ONLY"]),
        (
            "default",
            vec![
                "LEGACY",
                "NON_SECRET",
                "OPENAI_API_KEY",
                "default/CANONICAL",
            ],
        ),
        ("absent", vec![]),
    ] {
        for json in [false, true] {
            let mut cmd = phantom(&dir);
            cmd.args(["list", "--scope", scope, "--show-expiry"]);
            if json {
                cmd.arg("--json");
            }
            let output = cmd.output().unwrap();
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(!stdout.contains(fixture_value));
            assert!(!stderr.contains(fixture_value));
            assert!(!stdout.contains("phm_"));
            assert!(!stderr.contains("phm_"));
            assert!(!stdout.contains("sk-test-openai-value"));
            assert!(!stderr.contains("sk-test-openai-value"));
            if json {
                let entries: Vec<Value> = serde_json::from_str(&stdout).unwrap();
                let names: Vec<_> = entries
                    .iter()
                    .map(|entry| entry["name"].as_str().unwrap())
                    .collect();
                assert_eq!(names, expected);
                assert!(entries.iter().all(|entry| entry.get("value").is_none()));
            } else {
                for name in &expected {
                    assert!(stdout.contains(name));
                }
                for other in [
                    "dev/DEV_ONLY",
                    "staging/STAGING_ONLY",
                    "prod/PROD_ONLY",
                    "development/OTHER",
                ] {
                    if !expected.contains(&other) {
                        assert!(!stdout.contains(other));
                    }
                }
            }
        }
    }
    for invalid in ["../prod", "prod/x", "", "a b"] {
        phantom(&dir)
            .args(["list", "--scope", invalid])
            .assert()
            .failure();
    }
    assert_eq!(fs::read(encrypted).unwrap(), before);
    assert_eq!(fs::read(selector).unwrap(), b"staging\n");
    assert_eq!(
        fs::read(dir.path().join(".phantom.toml")).unwrap(),
        config_before
    );
    assert_eq!(fs::read(dir.path().join(".env")).unwrap(), dotenv_before);
}
