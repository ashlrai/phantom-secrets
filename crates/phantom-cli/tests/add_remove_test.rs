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
        .args(["add", "MY_KEY", "--stdin"])
        .write_stdin("my-value\n")
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
fn headless_remove_is_denied_and_preserves_the_key() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // Add the key first
    phantom(&dir)
        .args(["add", "MY_KEY", "--stdin"])
        .write_stdin("my-value\n")
        .assert()
        .success();

    // Destructive removal requires a separately controlled attached terminal.
    // A headless agent or script must fail before changing vault or dotenv state.
    let denied = phantom(&dir).args(["remove", "MY_KEY"]).assert().failure();
    assert!(String::from_utf8_lossy(&denied.get_output().stderr)
        .contains("requires attached stdin, stdout, and stderr terminals"));

    // The key must remain after the denied headless attempt.
    let output = phantom(&dir).arg("list").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("MY_KEY"),
        "MY_KEY should remain after denied headless removal, got: {stdout}"
    );
    let dotenv = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(dotenv.contains("MY_KEY=phm_"), "{dotenv}");
}

#[test]
fn add_without_init_fails_before_project_mutation() {
    let dir = TempDir::new().unwrap();
    let output = phantom(&dir)
        .args(["add", "SOME_KEY", "--stdin"])
        .write_stdin("some-value\n")
        .assert()
        .failure();
    assert!(String::from_utf8_lossy(&output.get_output().stderr).contains("phantom init --empty"));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn add_to_empty_initialized_project_persists_managed_dotenv_mapping() {
    let dir = TempDir::new().unwrap();
    phantom(&dir).args(["init", "--empty"]).assert().success();
    phantom(&dir)
        .args(["add", "SOME_KEY", "--stdin"])
        .write_stdin("some-value\n")
        .assert()
        .success();

    let config = fs::read_to_string(dir.path().join(".phantom.toml")).unwrap();
    let dotenv = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(config.contains("dotenv_path = \".env\""), "{config}");
    assert!(dotenv.contains("SOME_KEY=phm_"), "{dotenv}");
    assert!(!dotenv.contains("some-value"));
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
        .args(["add", "MY_NEW_KEY", "--stdin"])
        .write_stdin("my-real-value\n")
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
