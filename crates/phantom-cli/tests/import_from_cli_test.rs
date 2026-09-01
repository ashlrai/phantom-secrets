use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

const VAULT_PASS: &str = "competitor-import-cli-test-passphrase";
const IMPORTED_VALUE: &str = "test-only-imported-value";

fn phantom(dir: &TempDir) -> Command {
    let mut command = Command::cargo_bin("phantom").unwrap();
    command
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS);
    command
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn competitor_import_headless_denial_precedes_project_and_source_access() {
    let dir = TempDir::new().unwrap();
    let output = phantom(&dir)
        .args([
            "import",
            "--from",
            "doppler",
            "--file",
            "missing.json",
            "--force",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = combined_output(&output);
    assert!(message.contains("stdin, stdout, and stderr attached to a trusted terminal"));
    assert!(!message.contains("No .phantom.toml"));
    assert!(!message.contains("Cannot open import file"));
    assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[test]
fn competitor_import_force_cannot_mutate_vault_without_terminal_consent() {
    let dir = TempDir::new().unwrap();
    phantom(&dir).args(["init", "--empty"]).assert().success();
    let source = dir.path().join("doppler.json");
    fs::write(
        &source,
        format!(r#"{{"IMPORTED_TEST_SECRET":"{IMPORTED_VALUE}"}}"#),
    )
    .unwrap();
    let source_before = fs::read(&source).unwrap();

    let output = phantom(&dir)
        .args([
            "import",
            "--from",
            "doppler",
            "--file",
            "doppler.json",
            "--force",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = combined_output(&output);
    assert!(message.contains("stdin, stdout, and stderr attached to a trusted terminal"));
    assert!(!message.contains(IMPORTED_VALUE));
    assert_eq!(fs::read(&source).unwrap(), source_before);

    let listed = phantom(&dir).args(["list", "--json"]).output().unwrap();
    assert!(listed.status.success(), "{}", combined_output(&listed));
    let list_output = combined_output(&listed);
    assert!(!list_output.contains("IMPORTED_TEST_SECRET"));
    assert!(!list_output.contains(IMPORTED_VALUE));
}
