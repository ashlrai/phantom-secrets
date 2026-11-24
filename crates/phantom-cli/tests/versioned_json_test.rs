//! Versioned receipts contain metadata only; command failures use a safe envelope.
mod common;

use serde_json::{json, Value};
use std::process::Output;
use tempfile::TempDir;

fn run(dir: &TempDir, args: &[&str]) -> Output {
    common::phantom(dir, "plain")
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("PHANTOM_AUDIT")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .unwrap()
}

fn report(output: &Output) -> Value {
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn env_json_reports_counts_without_values_and_keeps_human_output() {
    let dir = common::canonical_tempdir();
    std::fs::write(dir.path().join(".env"), "API_KEY=pear\nMODE=quiet\n").unwrap();
    let output = run(&dir, &["env", "--json"]);
    assert_eq!(
        report(&output),
        json!({
            "schema": "env.v1", "written": true, "output": ".env.example",
            "secrets_masked": 1, "config_preserved": 1,
            "durability_verified": true, "warnings": [],
        })
    );
    let human = run(&dir, &["env", "--output", "example"]);
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("Generated example"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("pear"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("pear"));
    std::fs::write(dir.path().join(".env"), "").unwrap();
    assert_eq!(
        report(&run(&dir, &["--json", "env", "--output", "empty"])),
        json!({
            "schema": "env.v1", "written": false,
            "durability_verified": true, "warnings": [],
        })
    );
    assert!(!dir.path().join("empty").exists());
}

#[test]
fn audit_path_json_matches_the_human_path_with_either_flag_position() {
    let dir = common::canonical_tempdir();
    let human = run(&dir, &["audit", "path"]);
    assert!(human.status.success());
    let path = String::from_utf8(human.stdout).unwrap();
    for args in [["--json", "audit", "path"], ["audit", "path", "--json"]] {
        assert_eq!(
            report(&run(&dir, &args)),
            json!({
                "schema": "audit.path.v1", "path": path.trim(),
            })
        );
    }
}

#[test]
fn generated_add_json_has_only_a_name_and_fingerprint() {
    let dir = common::canonical_tempdir();
    assert!(run(&dir, &["init", "--empty"]).status.success());
    let receipt = report(&run(&dir, &["--json", "add", "PEAR", "--generate"]));
    assert_eq!(receipt["schema"], "add.v1");
    assert_eq!(receipt["name"], "PEAR");
    assert!(receipt["fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(receipt["durability_verified"], true);
    assert!(receipt["warnings"].as_array().unwrap().is_empty());
    assert_eq!(receipt.as_object().unwrap().len(), 5);
    assert!(receipt.get("durability_verified").is_some());
}

#[test]
fn command_errors_are_json_on_stderr_without_input_or_parser_details() {
    let dir = common::canonical_tempdir();
    std::fs::write(dir.path().join(".phantom.toml"), "pear").unwrap();
    for args in [
        vec!["env", "--json"],
        vec!["add", "PEAR", "--generate", "--json"],
    ] {
        let output = run(&dir, &args);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(
            error,
            json!({ "schema": "error.v1", "code": "command_failed",
            "message": "Command failed; run without --json for details." })
        );
    }
}
