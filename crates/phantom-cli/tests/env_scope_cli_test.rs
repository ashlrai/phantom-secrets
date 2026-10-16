/// Integration tests for the `phantom env` scope subcommands.
mod common;

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "test-integration-passphrase-env-scope";

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path());
    cmd
}

fn run(dir: &TempDir, args: &[&str]) -> (bool, String, String) {
    let out = phantom(dir).args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn init_project(dir: &TempDir) {
    fs::write(
        dir.path().join(".env"),
        "OPENAI_API_KEY=sk-test-env-scope-value\n",
    )
    .unwrap();
    phantom(dir)
        .args(["init", "--from", ".env"])
        .assert()
        .success();
}

#[test]
fn env_list_shows_default_as_active() {
    let dir = common::canonical_tempdir();
    init_project(&dir);
    let (ok, out, _) = run(&dir, &["env", "list"]);
    assert!(ok);
    assert!(out.contains("default") && out.contains("(active)"));
    assert!(!out.contains("sk-test-env-scope-value"));
}

#[test]
fn env_new_declares_without_touching_values() {
    let dir = common::canonical_tempdir();
    init_project(&dir);
    let (ok, out, _) = run(&dir, &["env", "new", "staging"]);
    assert!(ok);
    assert!(out.contains("phantom env copy --from default --to staging"));
}

#[test]
fn env_new_rejects_invalid_names() {
    let dir = common::canonical_tempdir();
    init_project(&dir);
    phantom(&dir)
        .args(["env", "new", "../escape"])
        .assert()
        .failure();
}

#[test]
fn env_subcommands_require_initialized_project() {
    let dir = common::canonical_tempdir();
    let (ok, _, err) = run(&dir, &["env", "list"]);
    assert!(!ok);
    assert!(err.contains(".phantom.toml"));
}

#[test]
fn env_example_subcommand_and_legacy_form_both_work() {
    let dir = common::canonical_tempdir();
    init_project(&dir);
    phantom(&dir)
        .args(["env", "example", "-o", "a.example"])
        .assert()
        .success();
    phantom(&dir)
        .args(["env", "-o", "b.example"])
        .assert()
        .success();
    for name in ["a.example", "b.example"] {
        let body = fs::read_to_string(dir.path().join(name)).unwrap();
        assert!(body.contains("OPENAI_API_KEY"));
        assert!(!body.contains("sk-test-env-scope-value"));
    }
}

#[test]
fn env_use_requires_trusted_terminal_or_succeeds_without_values() {
    let dir = common::canonical_tempdir();
    init_project(&dir);
    let out = phantom(&dir)
        .args(["env", "use", "staging"])
        .output()
        .unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!all.contains("sk-test-env-scope-value"));
}
