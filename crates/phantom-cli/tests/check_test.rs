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
    let dir = TempDir::new().unwrap();
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
