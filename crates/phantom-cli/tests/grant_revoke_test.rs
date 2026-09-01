mod common;

use assert_cmd::Command;
use phantom_core::config::PhantomConfig;
use phantom_core::rotation_provider::RotationProviderConfig;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const VAULT_PASS: &str = "grant-revoke-fail-closed-test-passphrase";
const ROOT_VALUE: &str = "test-only-github-app-root-material";

fn command(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").unwrap();
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .env_remove("PHANTOM_AUDIT");
    cmd
}

fn setup_github_grant() -> TempDir {
    let dir = common::canonical_tempdir();
    command(&dir).args(["init", "--empty"]).assert().success();
    command(&dir)
        .args(["add", "GITHUB_APP_PEM", "--stdin"])
        .write_stdin(format!("{ROOT_VALUE}\n"))
        .assert()
        .success();

    let path = dir.path().join(".phantom.toml");
    let mut config = PhantomConfig::load(&path).unwrap();
    let rotation = RotationProviderConfig {
        provider: "github".to_string(),
        api_key_env: Some("GITHUB_APP_PEM".to_string()),
        ..RotationProviderConfig::default()
    };
    config
        .phantom
        .secrets
        .entry("GITHUB_TOKEN".to_string())
        .or_default()
        .rotation_provider = Some(rotation);
    config.save(&path).unwrap();
    dir
}

fn collect_files(root: &Path, current: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
    if !current.exists() {
        return;
    }
    for entry in fs::read_dir(current).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            collect_files(root, &path, files);
        } else if file_type.is_file() {
            files.push((
                path.strip_prefix(root).unwrap().to_path_buf(),
                fs::read(path).unwrap(),
            ));
        }
    }
}

fn local_state_snapshot(dir: &TempDir) -> Vec<(PathBuf, Vec<u8>)> {
    let root = dir.path();
    let mut files = Vec::new();
    collect_files(root, root, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

#[test]
fn revoke_blocks_before_vault_or_config_mutation() {
    let dir = setup_github_grant();
    let config_path = dir.path().join(".phantom.toml");
    let before_config = fs::read(&config_path).unwrap();
    let before_state = local_state_snapshot(&dir);
    assert!(!before_state.is_empty());

    let output = command(&dir)
        .args(["grant", "revoke", "github-app"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Remote revocation"), "stderr={stderr}");
    assert!(stderr.contains("no local vault values"), "stderr={stderr}");
    assert!(
        stderr.contains("https://github.com/settings/apps"),
        "stderr={stderr}"
    );
    assert_eq!(fs::read(&config_path).unwrap(), before_config);
    assert_eq!(local_state_snapshot(&dir), before_state);
}

#[test]
fn revoke_json_reports_blocked_and_non_mutating() {
    let dir = setup_github_grant();
    let config_path = dir.path().join(".phantom.toml");
    let before_config = fs::read(&config_path).unwrap();
    let before_state = local_state_snapshot(&dir);

    let output = command(&dir)
        .args(["grant", "revoke", "github-app", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["state"], "blocked");
    assert_eq!(body["remote_revocation_required"], true);
    assert_eq!(body["local_mutation"], false);
    assert_eq!(body["value_printed"], false);
    assert!(body["guidance"]
        .as_str()
        .unwrap()
        .contains("github.com/settings/apps"));
    assert_eq!(fs::read(&config_path).unwrap(), before_config);
    assert_eq!(local_state_snapshot(&dir), before_state);
}
