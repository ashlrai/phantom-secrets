//! `phantom add --generate` stores a locally generated secret and prints only
//! a value-free receipt; existing names are refused before anything is read.

mod common;

use assert_cmd::Command;
#[cfg(unix)]
use phantom_vault::VaultBackend;
#[cfg(unix)]
use sha2::Digest;

const VAULT_PASS: &str = "generation-test-passphrase";

/// Resolve the file-vault directory the CLI subprocess uses, given the HOME
/// and XDG variables `command` sets. `directories::ProjectDirs` maps them
/// per-platform; mirrored here so the test can open the same vault. Windows
/// known-folder paths do not follow environment overrides, so the stored-value
/// assertions run on Unix only.
#[cfg(unix)]
fn vault_dir_for(home: &std::path::Path) -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support/ai.phantom.phantom-secrets")
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.join("data").join("phantom-secrets")
    }
}

fn command(dir: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("phantom").unwrap();
    command
        .current_dir(dir)
        .env("HOME", dir)
        .env("USERPROFILE", dir)
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("APPDATA", dir.join("appdata"))
        .env("LOCALAPPDATA", dir.join("localappdata"))
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("NO_COLOR", "1");
    command
}

#[cfg(unix)]
#[test]
fn generate_stdout_has_no_value_and_refuses_replacement() {
    let dir = common::canonical_tempdir();
    let expected_vault_dir = vault_dir_for(dir.path());
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
    let config =
        phantom_core::config::PhantomConfig::load(&dir.path().join(".phantom.toml")).unwrap();
    let vault = phantom_vault::file::FileVault::new(
        &expected_vault_dir,
        config.local_project_id(),
        VAULT_PASS.to_owned(),
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
    assert_eq!(
        receipt["fingerprint"],
        format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(value.as_bytes()))
        )
    );
    assert!(!String::from_utf8_lossy(bytes).contains("phm_"));
    command(dir.path())
        .args(["add", "GENERATED_KEY", "--generate"])
        .assert()
        .failure();
}

#[test]
fn generate_conflicts_with_input_modes() {
    let dir = common::canonical_tempdir();
    for flag in ["--stdin", "--multiline", "--first-line", "--dry-run"] {
        command(dir.path())
            .args(["add", "KEY", "--generate", flag])
            .assert()
            .failure();
    }
    command(dir.path())
        .args(["add", "KEY", "--generate", "positional-value"])
        .assert()
        .failure();
}
