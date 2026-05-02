/// Integration tests for `phantom add KEY --stdin`.
///
/// These tests verify that piping a secret value via stdin (with --stdin flag)
/// correctly stores the secret in the vault, and that passing no value and no
/// --stdin when stdin is not a tty fails with a clear error.
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "test-integration-passphrase-add-stdin";

fn init_project(dir: &TempDir) {
    // Use a value that phantom's heuristics flag as a real secret (starts with sk-).
    fs::write(dir.path().join(".env"), "SEED_SECRET=sk-seed-value\n").expect("write seed .env");

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
fn add_stdin_stores_secret_in_vault() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // Pipe the secret value via stdin using --stdin flag.
    phantom(&dir)
        .args(["add", "STRIPE_WEBHOOK_SECRET", "--stdin"])
        .write_stdin("whsec_test_value_from_pipe\n")
        .assert()
        .success();

    // Verify the key appears in `phantom list`.
    let output = phantom(&dir).arg("list").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("STRIPE_WEBHOOK_SECRET"),
        "STRIPE_WEBHOOK_SECRET should appear in list after --stdin add, got: {stdout}"
    );
}

#[test]
fn add_stdin_trims_trailing_newline() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // The trimmed value must be stored (no trailing \n).
    phantom(&dir)
        .args(["add", "TRIMMED_KEY", "--stdin"])
        .write_stdin("actual_value\n")
        .assert()
        .success();

    let output = phantom(&dir).arg("list").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("TRIMMED_KEY"), "got: {stdout}");
}

#[test]
fn add_stdin_empty_value_fails() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // An empty stdin line must be rejected.
    phantom(&dir)
        .args(["add", "EMPTY_KEY", "--stdin"])
        .write_stdin("\n")
        .assert()
        .failure();
}

#[test]
fn add_stdin_updates_env_file_with_phantom_token() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    phantom(&dir)
        .args(["add", "PIPED_KEY", "--stdin"])
        .write_stdin("piped-real-value\n")
        .assert()
        .success();

    let env_content = fs::read_to_string(dir.path().join(".env")).expect("read .env");
    assert!(
        env_content.contains("PIPED_KEY=phm_"),
        ".env should have a phantom token for PIPED_KEY, got: {env_content}"
    );
    assert!(
        !env_content.contains("piped-real-value"),
        "real value must not appear in .env"
    );
}

#[test]
fn add_no_value_no_stdin_on_non_tty_fails() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // When stdin is a pipe (assert_cmd pipes stdin by default) and neither
    // a positional value nor --stdin is given, phantom must fail rather than hang.
    phantom(&dir)
        .args(["add", "SOME_KEY"])
        .write_stdin("ignored\n") // stdin is a pipe, not a tty
        .assert()
        .failure();
}
