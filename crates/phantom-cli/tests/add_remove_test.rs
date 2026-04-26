/// Integration tests for `phantom add`, `phantom list`, and `phantom remove`.
///
/// Flow: init a project in a tempdir, then add/list/remove a key and assert
/// the vault state is reflected correctly in `phantom list` output.
///
/// All commands run in the same TempDir so they share the same `.phantom.toml`
/// and therefore the same vault project_id.
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "test-integration-passphrase-add-remove";

/// Initialise a fresh project in `dir` and return the TempDir (kept alive).
fn init_project(dir: &TempDir) {
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
fn add_then_list_shows_key() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // Add a new secret
    phantom(&dir)
        .args(["add", "MY_KEY", "my-value"])
        .assert()
        .success();

    // List should contain the key name
    let output = phantom(&dir).arg("list").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("MY_KEY"),
        "MY_KEY should appear in list output, got: {stdout}"
    );
}

#[test]
fn remove_makes_key_disappear_from_list() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // Add the key first
    phantom(&dir)
        .args(["add", "MY_KEY", "my-value"])
        .assert()
        .success();

    // Remove it
    phantom(&dir).args(["remove", "MY_KEY"]).assert().success();

    // List should no longer contain the key
    let output = phantom(&dir).arg("list").assert();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        !stdout.contains("MY_KEY"),
        "MY_KEY should not appear after removal, got: {stdout}"
    );
}

#[test]
fn add_without_init_fails() {
    // No init — .phantom.toml does not exist
    let dir = TempDir::new().unwrap();
    phantom(&dir)
        .args(["add", "SOME_KEY", "some-value"])
        .assert()
        .failure();
}

#[test]
fn list_shows_seed_secret_after_init() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    let output = phantom(&dir).arg("list").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("SEED_SECRET"),
        "SEED_SECRET from .env should appear in list after init, got: {stdout}"
    );
}

#[test]
fn add_updates_env_file_with_phantom_token() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    phantom(&dir)
        .args(["add", "MY_NEW_KEY", "my-real-value"])
        .assert()
        .success();

    let env_content = fs::read_to_string(dir.path().join(".env")).expect("read .env");
    assert!(
        env_content.contains("MY_NEW_KEY=phm_"),
        ".env should contain a phantom token for MY_NEW_KEY, got: {env_content}"
    );
    assert!(
        !env_content.contains("my-real-value"),
        "real value must not appear in .env"
    );
}
