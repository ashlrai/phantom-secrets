/// Integration tests for owner-scope labels and the cross-owner copy guard.
mod common;

use assert_cmd::Command;
use std::fs;
use std::path::Path;

const VAULT_PASS: &str = "test-integration-passphrase-owner-scope";
const VALUE: &str = "sk-test-owner-scope-value";

fn phantom(dir: &Path, home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir)
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", home);
    cmd
}

fn label(dir: &Path, owner: &str) {
    let path = dir.join(".phantom.toml");
    let body = fs::read_to_string(&path).unwrap();
    let labelled = body.replacen(
        "[phantom]\n",
        &format!("[phantom]\nowner = \"{owner}\"\n"),
        1,
    );
    assert_ne!(body, labelled, "expected a [phantom] table");
    fs::write(&path, labelled).unwrap();
}

fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = common::canonical_tempdir();
    let src = root.path().join("client-repo");
    let dst = root.path().join("personal-repo");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    fs::write(src.join(".env"), format!("OPENAI_API_KEY={VALUE}\n")).unwrap();
    phantom(&src, root.path())
        .args(["init", "--from", ".env"])
        .assert()
        .success();
    phantom(&dst, root.path())
        .args(["init", "--empty"])
        .assert()
        .success();
    (root, src, dst)
}

#[test]
fn cross_owner_copy_is_refused_without_flag() {
    let (root, src, dst) = setup();
    label(&src, "client:globex");
    label(&dst, "personal");
    let out = phantom(&src, root.path())
        .args(["copy", "OPENAI_API_KEY", "--to"])
        .arg(&dst)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("Refusing to copy across owners"),
        "{stderr}"
    );
    assert!(!stderr.contains(VALUE));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(VALUE));
}

#[test]
fn invalid_owner_label_is_rejected_on_load() {
    let (root, src, _dst) = setup();
    label(&src, "Client:Bad/Name");
    phantom(&src, root.path())
        .args(["status"])
        .assert()
        .failure();
}

#[test]
fn same_owner_copy_passes_the_owner_guard() {
    let (root, src, dst) = setup();
    label(&src, "client:globex");
    label(&dst, "client:globex");
    let out = phantom(&src, root.path())
        .args(["copy", "OPENAI_API_KEY", "--to"])
        .arg(&dst)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Without a trusted terminal the copy stops at its confirmation step,
    // but it must not be stopped by the owner guard.
    assert!(
        !stderr.contains("Refusing to copy across owners"),
        "{stderr}"
    );
    assert!(!stderr.contains(VALUE));
}
