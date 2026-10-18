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

/// Only services with a vaulted credential are rerouted. A base URL for an
/// unvaulted service (ANTHROPIC_BASE_URL in an OpenAI-only project) would send
/// the child's SDK, including `phantom exec -- claude`, to a proxy route that
/// can only answer 503 "route credential unavailable".
#[cfg(unix)]
#[test]
fn exec_routes_only_vaulted_services() {
    let (project, home) = initialized_project();

    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--", "sh", "-c"])
        .arg("printf 'OPENAI=%s\\nANTHROPIC=%s\\n' \"${OPENAI_BASE_URL-unset}\" \"${ANTHROPIC_BASE_URL-unset}\"")
        .output()
        .unwrap();
    assert_success(&output, "phantom exec");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let field = |key: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("{key} missing from child output:\n{stdout}"))
            .to_string()
    };
    assert!(
        field("OPENAI").contains("/openai/_phantom/"),
        "child must still receive the OpenAI proxy base URL:\n{stdout}"
    );
    assert_eq!(
        field("ANTHROPIC"),
        "unset",
        "an unvaulted service must not be rerouted to a credential-less proxy route"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OPENAI_BASE_URL = "), "stderr:\n{stderr}");
    assert!(
        !stderr.contains("ANTHROPIC_BASE_URL = "),
        "stderr:\n{stderr}"
    );
}

/// A protected key with no proxy route reaches the child only as a session
/// token that no provider accepts. Exec must say so instead of counting it as
/// proxied, even under `--quiet` (warnings are not progress).
#[test]
fn exec_warns_about_protected_keys_without_a_route() {
    use rand::RngCore;
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    // Values are generated per run; only the key names matter here.
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    let routed_value = format!("routed-{}", hex::encode(bytes));
    rand::thread_rng().fill_bytes(&mut bytes);
    let unrouted_value = format!("unrouted-{}", hex::encode(bytes));
    fs::write(
        project.path().join(".env"),
        format!("OPENAI_API_KEY={routed_value}\nGROQ_API_KEY={unrouted_value}\n"),
    )
    .unwrap();
    let output = phantom_command(project.path(), home.path())
        .args(["init", "--from", ".env"])
        .output()
        .unwrap();
    assert_success(&output, "phantom init");

    for (args, quiet) in [
        (&["exec", "--"][..], false),
        (&["--quiet", "exec", "--"][..], true),
    ] {
        let output = phantom_command(project.path(), home.path())
            .args(args)
            .arg(phantom_binary())
            .arg("--version")
            .output()
            .unwrap();
        assert_success(&output, "phantom exec");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.replace("\r\n", "\n"), expected_child_stdout());
        let stderr = String::from_utf8_lossy(&output.stderr);
        let warning = stderr
            .lines()
            .find(|line| line.contains("No proxy route"))
            .unwrap_or_else(|| panic!("{args:?} printed no route warning:\n{stderr}"));
        assert!(warning.contains("GROQ_API_KEY"), "{warning}");
        assert!(!warning.contains("OPENAI_API_KEY"), "{warning}");
        if !quiet {
            assert!(
                stderr.contains("1 secret(s) proxied"),
                "only the routed key is proxied:\n{stderr}"
            );
        }
        for value in [&routed_value, &unrouted_value] {
            assert!(!stderr.contains(value.as_str()), "value leaked:\n{stderr}");
        }
    }
}
