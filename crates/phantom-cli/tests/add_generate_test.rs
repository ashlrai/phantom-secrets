mod common;
use assert_cmd::Command;
use phantom_vault::VaultBackend;
use sha2::{Digest, Sha256};

fn command(dir: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("phantom").unwrap();
    command
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
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
    // Discover only fixture-owned file metadata. ProjectDirs uses platform
    // data directories rather than <HOME>/.phantom on macOS and Linux.
    let mut directories = vec![dir.path().to_path_buf()];
    let mut vault_roots = Vec::new();
    let filename = format!("{}.vault", project_id.local_project_id());
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directories.push(entry.path());
            } else if entry.file_name() == filename.as_str() {
                vault_roots.push(
                    entry
                        .path()
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .to_path_buf(),
                );
            }
        }
    }
    assert_eq!(vault_roots.len(), 1, "expected one fixture-owned vault");
    let vault = phantom_vault::file::FileVault::new(
        &vault_roots[0],
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

#[test]
fn generated_fulfillment_preserves_request_mapping_and_metadata_is_value_blind() {
    let dir = common::canonical_tempdir();
    command(dir.path())
        .args(["init", "--empty"])
        .assert()
        .success();
    let requested = command(dir.path())
        .args(["request", "SESSION_SECRET", "--purpose", "session signing"])
        .output()
        .unwrap();
    assert!(
        requested.status.success(),
        "request failed (output withheld)"
    );
    let config_path = dir.path().join(".phantom.toml");
    let pending = phantom_core::config::PhantomConfig::load(&config_path).unwrap();
    let placeholder = &pending.requests["SESSION_SECRET"].placeholder;
    let generated = command(dir.path())
        .args(["add", "SESSION_SECRET", "--generate"])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "generation failed (output withheld)"
    );
    let fulfilled = phantom_core::config::PhantomConfig::load(&config_path).unwrap();
    assert_eq!(
        fulfilled.requests["SESSION_SECRET"].status,
        phantom_core::config::RequestStatus::Fulfilled
    );
    assert!(fulfilled.requests["SESSION_SECRET"].placeholder == *placeholder);
    let dotenv = std::fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(dotenv.contains(placeholder), "reserved mapping changed");
    let metadata = command(dir.path())
        .args(["get", "SESSION_SECRET"])
        .output()
        .unwrap();
    assert!(
        metadata.status.success(),
        "metadata lookup failed (output withheld)"
    );
    let receipt: serde_json::Value = serde_json::from_slice(&metadata.stdout).unwrap();
    assert_eq!(receipt["exists"], true);
    assert_eq!(receipt["vault_inspected"], false);
    for output in [&generated, &metadata] {
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !String::from_utf8_lossy(bytes).contains(placeholder),
                "mapping leaked"
            );
        }
    }
}
