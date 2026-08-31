use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "competitor-import-cli-test-passphrase";

fn phantom(dir: &TempDir) -> Command {
    let mut command = Command::cargo_bin("phantom").unwrap();
    command
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS);
    command
}

#[test]
fn competitor_import_accepts_from_with_file_flag() {
    let dir = TempDir::new().unwrap();
    phantom(&dir).args(["init", "--empty"]).assert().success();
    fs::write(
        dir.path().join("doppler.json"),
        r#"{"IMPORTED_TEST_SECRET":"test-only-imported-value","DOPPLER_PROJECT":"ignored"}"#,
    )
    .unwrap();

    let imported = phantom(&dir)
        .args(["import", "--from", "doppler", "--file", "doppler.json"])
        .assert()
        .success();
    let import_stdout = String::from_utf8_lossy(&imported.get_output().stdout);
    assert!(
        import_stdout.contains("Imported 1 secret(s) from doppler"),
        "unexpected import output: {import_stdout}"
    );

    let listed = phantom(&dir).args(["list", "--json"]).assert().success();
    let list_stdout = String::from_utf8_lossy(&listed.get_output().stdout);
    assert!(list_stdout.contains("IMPORTED_TEST_SECRET"));
    assert!(!list_stdout.contains("test-only-imported-value"));
}
