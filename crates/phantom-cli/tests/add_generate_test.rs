mod common;
use assert_cmd::Command;
use phantom_vault::VaultBackend;
use sha2::{Digest, Sha256};

fn command(dir: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("phantom").unwrap();
    command
        .current_dir(dir)
        .env("HOME", dir)
        .env("PHANTOM_VAULT_PASSPHRASE", "generation-test-passphrase")
        .env("NO_COLOR", "1");
    command
}

#[test]
fn generate_stdout_has_no_value_and_refuses_replacement() {
    let dir = common::canonical_tempdir();
    command(dir.path())
        .args(["init", "--empty"])
        .assert()
        .success();
    let output = command(dir.path())
        .args(["add", "GENERATED_KEY", "--generate"])
        .assert()
        .success();
    let bytes = &output.get_output().stdout;
    let receipt: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(receipt.as_object().unwrap().len(), 2);
    assert_eq!(receipt["name"], "GENERATED_KEY");
    let project_id =
        phantom_core::config::PhantomConfig::load(&dir.path().join(".phantom.toml")).unwrap();
    let vault = phantom_vault::file::FileVault::new(
        &dir.path().join(".phantom"),
        project_id.local_project_id(),
        "generation-test-passphrase".to_owned(),
    );
    let vault = vault.unwrap();
    let value = vault.retrieve("GENERATED_KEY").unwrap();
    assert_eq!(value.len(), 64);
    assert!(
        !String::from_utf8_lossy(bytes).contains(value.as_str()),
        "stdout leaked value"
    );
    assert!(
        !String::from_utf8_lossy(&output.get_output().stderr).contains(value.as_str()),
        "stderr leaked value"
    );
    assert!(
        receipt["fingerprint"]
            == format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
    );
    let fingerprint = receipt["fingerprint"].as_str().unwrap();
    assert!(fingerprint.starts_with("sha256:"));
    assert_eq!(fingerprint.len(), 71);
    assert!(!String::from_utf8_lossy(bytes).contains("phm_"));
    command(dir.path())
        .args(["add", "GENERATED_KEY", "--generate"])
        .assert()
        .failure();
}

#[test]
fn generate_conflicts_with_input_modes() {
    let dir = common::canonical_tempdir();
    for flag in ["--stdin", "--multiline", "--first-line"] {
        command(dir.path())
            .args(["add", "KEY", "--generate", flag])
            .assert()
            .failure();
    }
}
