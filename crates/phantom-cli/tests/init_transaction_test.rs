mod common;

use assert_cmd::Command;
use std::process::Command as StdCommand;

fn git(project: &std::path::Path, args: &[&str]) {
    let output = StdCommand::new("git")
        .args(args)
        .current_dir(project)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unsafe_effective_hook_target_fails_before_secret_or_file_mutation() {
    let project = common::canonical_tempdir();
    git(project.path(), &["init", "--quiet"]);
    git(
        project.path(),
        &["config", "core.hooksPath", "blocked/hooks"],
    );
    std::fs::write(project.path().join("blocked"), "regular file\n").unwrap();
    let original_env = b"OPENAI_API_KEY=sk-transaction-sentinel-value\n";
    std::fs::write(project.path().join(".env"), original_env).unwrap();

    let output = Command::cargo_bin("phantom")
        .unwrap()
        .current_dir(project.path())
        .env("PHANTOM_VAULT_PASSPHRASE", "transaction-test-passphrase")
        .args(["init", "--from", ".env"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("secret(s) are now protected!"));
    assert!(stderr.contains("Pre-commit hook setup failed"));
    assert_eq!(
        std::fs::read(project.path().join(".env")).unwrap(),
        original_env
    );
    assert!(!project.path().join(".phantom.toml").exists());
    assert!(!project.path().join(".env.example").exists());
    assert!(!project.path().join("CLAUDE.md").exists());
}
