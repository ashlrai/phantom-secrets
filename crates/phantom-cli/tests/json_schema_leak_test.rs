//! `--json` reports for doctor, why, check, and agent doctor carry a schema
//! id, keep the command's exit status, and never print a planted secret value.
mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::process::Output;

const KEY: &str = "OPENAI_API_KEY";
const CANARY: &str = "sk-json-schema-canary-7f3a9c1e5b";

fn project() -> tempfile::TempDir {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("{KEY}={CANARY}\nPORT=3000\n"),
    )
    .unwrap();
    dir
}

fn phantom(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("PHANTOM_VAULT_PASSPHRASE", "test-passphrase-json-schema")
        .env("NO_COLOR", "1")
        .env_remove("PHANTOM_AUDIT")
        .output()
        .expect("run phantom")
}

fn assert_canary_absent(output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains(CANARY), "canary in stdout: {stdout}");
    assert!(!stderr.contains(CANARY), "canary in stderr: {stderr}");
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn doctor_json_schema_matches_human_exit_and_hides_the_value() {
    let dir = project();
    let human = phantom(dir.path(), &["doctor"]);
    let json = phantom(dir.path(), &["doctor", "--json"]);
    assert_eq!(human.status.code(), json.status.code());
    assert_canary_absent(&human);
    assert_canary_absent(&json);
    let report = json_stdout(&json);
    assert_eq!(report["schema"], "phantom.doctor.v1");
    assert!(report["ok"].is_boolean());
    assert!(report["issues"].is_number());
    assert!(!report.to_string().contains(CANARY));
}

#[test]
fn why_json_schema_matches_human_exit_and_hides_the_value() {
    let dir = project();
    let human = phantom(dir.path(), &["why", KEY]);
    let json = phantom(dir.path(), &["why", KEY, "--json"]);
    assert_eq!(human.status.code(), json.status.code());
    assert!(human.status.success());
    assert_canary_absent(&human);
    assert_canary_absent(&json);
    let report = json_stdout(&json);
    assert_eq!(report["schema"], "phantom.why.v1");
    assert_eq!(report["key"], KEY);
    assert_eq!(report["protected"], false);
    assert_eq!(report["found"], true);
    assert!(!report.to_string().contains(CANARY));
}

#[test]
fn check_json_schema_keeps_nonzero_exit_and_hides_the_value() {
    let dir = project();
    let human = phantom(dir.path(), &["check"]);
    let json = phantom(dir.path(), &["check", "--json"]);
    assert!(!human.status.success());
    assert!(!json.status.success());
    assert_eq!(human.status.code(), json.status.code());
    assert_canary_absent(&human);
    assert_canary_absent(&json);
    let report = json_stdout(&json);
    assert_eq!(report["schema"], "phantom.check.v1");
    assert_eq!(report["clean"], false);
    assert!(!report.to_string().contains(CANARY));
}

#[test]
fn agent_doctor_json_schema_hides_the_value_on_stdout_and_stderr() {
    let dir = project();
    let human = phantom(dir.path(), &["agent", "doctor"]);
    let json = phantom(dir.path(), &["agent", "doctor", "--json"]);
    assert_canary_absent(&human);
    assert_canary_absent(&json);
    let report = json_stdout(&json);
    assert_eq!(report["schema"], "phantom.agent.doctor.v1");
    assert_eq!(json.status.code(), Some(0));
    assert!(!report.to_string().contains(CANARY));
    assert!(!report.to_string().contains(KEY));
}
