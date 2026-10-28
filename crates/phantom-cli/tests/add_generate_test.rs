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

/// The encrypted-file vault base is the platform project-data directory under
/// the test HOME (e.g. `Library/Application Support/ai.phantom.phantom-secrets`
/// on macOS, `$XDG_DATA_HOME/phantom-secrets` on Linux). Discover it through the
/// vault file the CLI actually wrote instead of duplicating that layout logic.
fn vault_base(home: &std::path::Path) -> std::path::PathBuf {
    fn walk(dir: &std::path::Path) -> Option<std::path::PathBuf> {
        for entry in std::fs::read_dir(dir).ok()? {
            let path = entry.ok()?.path();
            if path.is_dir() {
                if let Some(found) = walk(&path) {
                    return Some(found);
                }
            } else if path.extension().is_some_and(|ext| ext == "vault") {
                return path
                    .parent()
                    .and_then(|vaults| vaults.parent())
                    .map(|base| base.to_path_buf());
            }
        }
        None
    }
    walk(home).expect("the generated vault file must exist under the test home")
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
        &vault_base(dir.path()),
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
