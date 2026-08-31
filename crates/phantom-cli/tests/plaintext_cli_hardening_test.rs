use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "plaintext-cli-hardening-test-passphrase";
const SECRET_VALUE: &str = "test-only-value-must-not-be-printed";

fn command(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").unwrap();
    cmd.current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env_remove("PHANTOM_TOKEN")
        .env_remove("PHANTOM_AUDIT");
    cmd
}

fn setup_secret() -> TempDir {
    let dir = TempDir::new().unwrap();
    command(&dir).args(["init", "--empty"]).assert().success();
    command(&dir)
        .args(["add", "TEST_SECRET", "--stdin"])
        .write_stdin(format!("{SECRET_VALUE}\n"))
        .assert()
        .success();
    dir
}

fn directory_entries(dir: &TempDir) -> Vec<String> {
    let mut entries = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

#[test]
fn reveal_yes_is_rejected_before_project_or_vault_access() {
    let dir = TempDir::new().unwrap();
    let output = command(&dir)
        .args(["reveal", "TEST_SECRET", "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--yes is no longer supported"));
    assert!(directory_entries(&dir).is_empty());
}

#[test]
fn reveal_requires_attached_input_and_error_terminals() {
    let dir = setup_secret();
    let output = command(&dir)
        .args(["reveal", "TEST_SECRET"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET_VALUE));
    assert!(String::from_utf8_lossy(&output.stderr).contains("attached stdin and stderr terminals"));
}

#[test]
fn plaintext_json_export_is_disabled_even_with_legacy_acknowledgement() {
    let dir = TempDir::new().unwrap();
    let output = command(&dir)
        .args(["export", "--json", "--allow-plaintext"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Plaintext JSON export is disabled"));
    assert!(directory_entries(&dir).is_empty());
}

#[test]
fn team_revoke_fails_before_auth_network_or_local_mutation() {
    let dir = TempDir::new().unwrap();
    let before = directory_entries(&dir);
    let output = command(&dir)
        .args(["team", "revoke", "team-test", "member-test", "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("atomic membership-removal"));
    assert_eq!(directory_entries(&dir), before);
}

#[test]
fn help_hides_legacy_plaintext_and_revocation_flags() {
    let dir = TempDir::new().unwrap();

    let reveal = command(&dir).args(["reveal", "--help"]).output().unwrap();
    assert!(reveal.status.success());
    assert!(!String::from_utf8_lossy(&reveal.stdout).contains("--yes"));

    let export = command(&dir).args(["export", "--help"]).output().unwrap();
    assert!(export.status.success());
    let export_help = String::from_utf8_lossy(&export.stdout);
    assert!(!export_help.contains("--allow-plaintext"));
    assert!(!export_help.contains("--json"));

    let team = command(&dir).args(["team", "--help"]).output().unwrap();
    assert!(team.status.success());
    assert!(!String::from_utf8_lossy(&team.stdout).contains("revoke"));
}

#[test]
fn exec_refuses_protected_connection_strings_before_launching_child() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".env"),
        "DATABASE_URL=postgresql://agent:must-not-leak@db.example.test/app\n",
    )
    .unwrap();

    command(&dir)
        .args(["init", "--from", ".env"])
        .assert()
        .success();

    let output = command(&dir)
        .args(["exec", "--", "phantom", "--version"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Refusing to expose connection-string secret"),
        "unexpected exec failure: {combined}"
    );
    assert!(!combined.contains("postgresql://"));
    assert!(!combined.contains("must-not-leak"));
    assert!(!combined.contains("Launching:"));
}
