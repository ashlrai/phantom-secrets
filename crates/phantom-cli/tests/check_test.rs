mod common;

use assert_cmd::Command;
use std::fs;
use std::process::Command as StdCommand;
use tempfile::TempDir;

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path()).env("HOME", dir.path());
    cmd
}

#[test]
fn check_staged_blocks_staged_env_plaintext_secret() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .expect("git init");

    fs::write(dir.path().join(".env"), "OPENAI_API_KEY=sk-staged-secret\n").expect("write .env");
    StdCommand::new("git")
        .args(["add", ".env"])
        .current_dir(dir.path())
        .output()
        .expect("git add");

    let output = phantom(&dir).args(["check", "--staged"]).assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("staged .env") && stderr.contains("OPENAI_API_KEY"),
        "staged .env secret should be reported, got: {stderr}"
    );
}

#[test]
fn check_never_reports_malformed_worktree_dotenv_clean() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        "SAFE_NAME=ordinary\nBROKEN_RECORD\n",
    )
    .unwrap();

    let output = phantom(&dir).arg("check").assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("malformed dotenv"),
        "unexpected error: {stderr}"
    );
    assert!(!String::from_utf8_lossy(&output.get_output().stdout)
        .contains("No unprotected secrets found"));
}

#[test]
fn check_never_reports_malformed_staged_dotenv_clean() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    fs::write(
        dir.path().join(".env"),
        "SAFE_NAME=ordinary\nBROKEN_RECORD\n",
    )
    .unwrap();
    StdCommand::new("git")
        .args(["add", ".env"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let output = phantom(&dir).args(["check", "--staged"]).assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("malformed dotenv"),
        "unexpected error: {stderr}"
    );
}

#[test]
fn check_never_reports_non_utf8_staged_dotenv_clean() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    fs::write(dir.path().join(".env"), b"API_KEY=ok\n\xff\xfe\n").unwrap();
    StdCommand::new("git")
        .args(["add", ".env"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let output = phantom(&dir).args(["check", "--staged"]).assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("not valid UTF-8") && stderr.contains("indeterminate"),
        "unexpected error: {stderr}"
    );
    assert!(!String::from_utf8_lossy(&output.get_output().stdout)
        .contains("No unprotected secrets found"));
}

#[test]
fn check_staged_allows_unrelated_binary_asset() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    fs::write(
        dir.path().join("asset.png"),
        b"\x89PNG\r\n\x1a\n\0\xff\xfe\0binary-payload",
    )
    .unwrap();
    StdCommand::new("git")
        .args(["add", "asset.png"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    phantom(&dir).args(["check", "--staged"]).assert().success();
}

#[cfg(unix)]
#[test]
fn check_staged_handles_newline_in_filename_without_splitting_paths() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    let name = "safe\nnotes.txt";
    fs::write(dir.path().join(name), "ordinary staged text\n").unwrap();
    StdCommand::new("git")
        .arg("add")
        .arg(name)
        .current_dir(dir.path())
        .output()
        .unwrap();

    phantom(&dir).args(["check", "--staged"]).assert().success();
}

#[test]
fn ordinary_check_does_not_require_git_repository() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".env"), "APP_MODE=development\n").unwrap();

    phantom(&dir).arg("check").assert().success();
}

#[test]
fn check_staged_warns_on_risky_phantom_config_without_blocking() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .expect("git init");

    fs::write(
        dir.path().join(".phantom.toml"),
        r#"
[phantom]
version = "1"
project_id = "abc"

[services.openai]
secret_key = "OPENAI_API_KEY"
pattern = "attacker.example.com"
header = "Authorization"
header_format = "Bearer {secret}"
secret_type = "api_key"
"#,
    )
    .expect("write .phantom.toml");
    StdCommand::new("git")
        .args(["add", ".phantom.toml"])
        .current_dir(dir.path())
        .output()
        .expect("git add");

    let output = phantom(&dir).args(["check", "--staged"]).assert().success();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("Risky Phantom service route") && stderr.contains("OPENAI_API_KEY"),
        "risky .phantom.toml route should be advisory, got: {stderr}"
    );
}

#[test]
fn check_staged_scans_only_added_code_lines() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .expect("git init");
    StdCommand::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(dir.path())
        .output()
        .expect("git config email");
    StdCommand::new("git")
        .args(["config", "user.name", "Test User"])
        .current_dir(dir.path())
        .output()
        .expect("git config name");

    let documented_placeholder = format!("{}{}", "sk", "-example");
    fs::write(
        dir.path().join("README.md"),
        format!("Existing documented placeholder: {documented_placeholder}\n"),
    )
    .expect("write readme");
    StdCommand::new("git")
        .args(["add", "README.md"])
        .current_dir(dir.path())
        .output()
        .expect("git add");
    StdCommand::new("git")
        .args(["commit", "-m", "seed"])
        .current_dir(dir.path())
        .output()
        .expect("git commit");

    fs::write(
        dir.path().join("README.md"),
        format!("Existing documented placeholder: {documented_placeholder}\n\nSafe new line\n"),
    )
    .expect("update readme");
    StdCommand::new("git")
        .args(["add", "README.md"])
        .current_dir(dir.path())
        .output()
        .expect("git add");

    phantom(&dir).args(["check", "--staged"]).assert().success();
}
