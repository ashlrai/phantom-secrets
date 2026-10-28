mod common;

use assert_cmd::Command;
use std::fs;

fn phantom(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("phantom").unwrap();
    command
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", "synthetic-git-test-passphrase");
    command
}

#[test]
fn github_credential_flows_from_project_vault_to_pipe() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        "GITHUB_TOKEN=ghp_synthetic_git_credential_fixture_123456789\n",
    )
    .unwrap();
    phantom(&dir)
        .args(["init", "--from", ".env"])
        .assert()
        .success();
    let result = phantom(&dir)
        .args(["git-credential", "get"])
        .write_stdin("protocol=https\nhost=github.com\n\n")
        .assert()
        .success();
    assert_eq!(
        result.get_output().stdout,
        b"username=x-access-token\npassword=ghp_synthetic_git_credential_fixture_123456789\n\n"
    );
    assert!(result.get_output().stderr.is_empty());

    // An explicit missing entry must never fall back to the default token.
    phantom(&dir)
        .args(["git-credential", "--secret", "MISSING_ENTRY", "get"])
        .write_stdin("protocol=https\nhost=github.com\n\n")
        .assert()
        .failure()
        .stdout("");

    // Exercise Git itself as the pipe reader, with other helpers disabled.
    let helper = format!(
        "!'{}' git-credential",
        env!("CARGO_BIN_EXE_phantom").replace('\'', "'\"'\"'")
    );
    let mut git = Command::new("git");
    git.current_dir(dir.path()).env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", "synthetic-git-test-passphrase")
        .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", "credential.helper=", "-c", &format!("credential.helper={helper}"), "credential", "fill"])
        .write_stdin("protocol=https\nhost=github.com\n\n")
        .assert().success()
        .stdout("protocol=https\nhost=github.com\nusername=x-access-token\npassword=ghp_synthetic_git_credential_fixture_123456789\n");
}

#[test]
fn unrelated_hosts_and_write_operations_never_open_a_vault() {
    let dir = common::canonical_tempdir();
    for host in ["example.com", "github.com:443", "github.com.attacker"] {
        phantom(&dir)
            .args(["git-credential", "get"])
            .write_stdin(format!("protocol=https\nhost={host}\n\n"))
            .assert()
            .success()
            .stdout("");
    }
    for operation in ["store", "erase"] {
        phantom(&dir)
            .args(["git-credential", operation])
            .write_stdin("protocol=https\nhost=github.com\npassword=synthetic-only\n\n")
            .assert()
            .success()
            .stdout("")
            .stderr("");
    }
    assert!(!dir.path().join(".phantom.toml").exists());
}

#[test]
fn json_and_unknown_operations_are_rejected() {
    let dir = common::canonical_tempdir();
    phantom(&dir)
        .args(["git-credential", "get", "--json"])
        .assert()
        .failure()
        .stdout("");
    phantom(&dir)
        .args(["git-credential", "unexpected"])
        .assert()
        .failure()
        .stdout("");
}

#[cfg(unix)]
#[test]
fn stdout_file_is_refused_before_reading_input_or_vault() {
    let dir = common::canonical_tempdir();
    let path = dir.path().join("output");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_phantom"))
        .args(["git-credential", "get"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .stdin(std::process::Stdio::null())
        .stdout(fs::File::create(&path).unwrap())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(fs::read(path).unwrap().is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("stdout to be a pipe"));
}

#[cfg(unix)]
#[test]
fn tty_stdout_is_refused() {
    use std::os::fd::FromRawFd;
    let dir = common::canonical_tempdir();
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: valid writable fd pointers, with no name/termios/winsize requested.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(result, 0);
    // SAFETY: successful openpty returned two newly owned descriptors.
    let (_master, slave) = unsafe { (fs::File::from_raw_fd(master), fs::File::from_raw_fd(slave)) };
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_phantom"))
        .args(["git-credential", "get"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .stdin(std::process::Stdio::null())
        .stdout(slave)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("stdout to be a pipe"));
}

#[test]
fn malformed_requests_and_missing_vault_never_emit_credentials() {
    let dir = common::canonical_tempdir();
    for request in [
        "protocol=https\nhost=github.com\nhost=attacker\n\n",
        "protocol=https\nhost=github.com\n",
        "protocol=https\nhost=github.com\n\n",
    ] {
        phantom(&dir)
            .args(["git-credential", "get"])
            .write_stdin(request)
            .assert()
            .failure()
            .stdout("");
    }
}

#[test]
fn git_approve_and_reject_are_quiet_noops_with_null_helper_stdout() {
    let dir = common::canonical_tempdir();
    let helper = format!(
        "!'{}' git-credential",
        env!("CARGO_BIN_EXE_phantom").replace('\'', "'\"'\"'")
    );
    for operation in ["approve", "reject"] {
        let mut git = Command::new("git");
        git.current_dir(dir.path()).env("HOME", dir.path())
            .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_TERMINAL_PROMPT", "0")
            .args(["-c", "credential.helper=", "-c", &format!("credential.helper={helper}"), "credential", operation])
            .write_stdin("protocol=https\nhost=github.com\nusername=synthetic-user\npassword=synthetic-fixture\n\n")
            .assert().success().stdout("").stderr("");
    }
}
