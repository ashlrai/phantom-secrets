//! `phantom exec` must not mix its own progress output into the child's
//! stdout, and the global `--quiet` flag must silence that progress.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VAULT_PASS: &str = "exec-output-streams-integration-passphrase";

fn phantom_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_phantom"))
}

fn phantom_command(project: &Path, home: &Path) -> Command {
    let mut command = Command::new(phantom_binary());
    command
        .current_dir(project)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("NO_COLOR", "1")
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS);
    command
}

fn assert_success(output: &Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn initialized_project() -> (tempfile::TempDir, tempfile::TempDir) {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    fs::write(
        project.path().join(".env"),
        "OPENAI_API_KEY=sk-exec-output-streams-test-value\n",
    )
    .unwrap();
    let output = phantom_command(project.path(), home.path())
        .args(["init", "--from", ".env"])
        .output()
        .unwrap();
    assert_success(&output, "phantom init");
    (project, home)
}

/// The child's own stdout, which is what `phantom --version` prints.
fn expected_child_stdout() -> String {
    format!("phantom {}\n", env!("CARGO_PKG_VERSION"))
}

#[test]
fn exec_keeps_child_stdout_byte_for_byte() {
    let (project, home) = initialized_project();

    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(phantom_binary())
        .arg("--version")
        .output()
        .unwrap();
    assert_success(&output, "phantom exec");

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.replace("\r\n", "\n"),
        expected_child_stdout(),
        "exec progress leaked into the child's stdout"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Proxy running on"), "stderr:\n{stderr}");
    assert!(stderr.contains("Launching:"), "stderr:\n{stderr}");
    assert!(stderr.contains("Done."), "stderr:\n{stderr}");
}

#[test]
fn exec_quiet_suppresses_progress_but_keeps_child_output() {
    let (project, home) = initialized_project();

    for quiet_args in [&["--quiet", "exec", "--"][..], &["exec", "-q", "--"][..]] {
        let output = phantom_command(project.path(), home.path())
            .args(quiet_args)
            .arg(phantom_binary())
            .arg("--version")
            .output()
            .unwrap();
        assert_success(&output, "phantom exec --quiet");

        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.replace("\r\n", "\n"), expected_child_stdout());
        let stderr = String::from_utf8_lossy(&output.stderr);
        for chatter in [
            "Starting proxy",
            "Proxy running",
            "_BASE_URL",
            "_phantom/",
            "Launching:",
            "Shutting down proxy",
            "Done.",
        ] {
            assert!(
                !stderr.contains(chatter),
                "{quiet_args:?} still printed {chatter:?}:\n{stderr}"
            );
        }
    }
}

#[test]
fn exec_quiet_still_propagates_child_exit_code() {
    let (project, home) = initialized_project();

    // `phantom definitely-not-a-command` exits non-zero via clap.
    let output = phantom_command(project.path(), home.path())
        .args(["--quiet", "exec", "--"])
        .arg(phantom_binary())
        .arg("definitely-not-a-command")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("Command exited with code"), "{stderr}");
    assert!(
        stderr.contains("definitely-not-a-command"),
        "child's own error must still reach stderr:\n{stderr}"
    );
}
