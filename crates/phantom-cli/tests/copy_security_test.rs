mod common;

use assert_cmd::Command;
use std::fs;

const VAULT_PASS: &str = "test-integration-passphrase-copy-security";

fn phantom(project: &std::path::Path, home: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("phantom").expect("binary not found");
    command
        .current_dir(project)
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", home);
    command
}

#[test]
fn headless_copy_denies_before_source_retrieval_or_target_mutation() {
    let root = common::canonical_tempdir();
    let source = root.path().join("source");
    let target = root.path().join("target");
    let home = root.path().join("home");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&home).unwrap();

    phantom(&source, &home)
        .args(["init", "--empty"])
        .assert()
        .success();
    phantom(&source, &home)
        .args(["add", "SOURCE_KEY", "--stdin"])
        .write_stdin("never-print-this-value\n")
        .assert()
        .success();
    phantom(&target, &home)
        .args(["init", "--empty"])
        .assert()
        .success();

    let target_config_before = fs::read(target.join(".phantom.toml")).unwrap();
    let source_dotenv_before = fs::read(source.join(".env")).unwrap();
    let output = phantom(&source, &home)
        .args([
            "copy",
            "SOURCE_KEY",
            "--to",
            target.to_str().unwrap(),
            "--rename",
            "TARGET_KEY",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stderr.contains("attached stdin, stdout, and stderr terminals"));
    assert!(stderr.contains("No source secret was read and no target state changed"));
    assert!(!stderr.contains("never-print-this-value"));
    assert!(!stdout.contains("never-print-this-value"));
    assert_eq!(
        fs::read(target.join(".phantom.toml")).unwrap(),
        target_config_before
    );
    assert!(!target.join(".env").exists());
    assert_eq!(fs::read(source.join(".env")).unwrap(), source_dotenv_before);

    let list = phantom(&target, &home).arg("list").assert().success();
    assert!(!String::from_utf8_lossy(&list.get_output().stdout).contains("TARGET_KEY"));
}
