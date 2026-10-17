//! `phantom exec` must not die on SIGTERM and orphan its child: it forwards
//! the signal, waits for the child, shuts the proxy down, and exits with the
//! child's status.
#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VAULT_PASS: &str = "exec-signal-integration-unlock-phrase";

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

fn initialized_project() -> (tempfile::TempDir, tempfile::TempDir) {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    fs::write(
        project.path().join(".env"),
        "OPENAI_API_KEY=sk-exec-signal-test-value\n",
    )
    .unwrap();
    let output = phantom_command(project.path(), home.path())
        .args(["init", "--from", ".env"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "phantom init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (project, home)
}

/// What happened after SIGTERM was sent to phantom alone.
struct Outcome {
    /// phantom's exit code; `None` if a signal killed it.
    code: Option<i32>,
    stderr: String,
    child_saw_term: bool,
}

/// Start `phantom exec -- sh -c <script>`, wait for the child to write its
/// pid to `$READY`, send SIGTERM to phantom only, and wait (bounded) for
/// phantom to exit. The child is killed afterwards if it outlived phantom,
/// so a regression fails the test instead of leaking an orphan.
fn exec_and_terminate_phantom(script: &str) -> Outcome {
    let (project, home) = initialized_project();
    let ready = project.path().join("ready");
    let marker = project.path().join("child-saw-term");
    let stderr_path = project.path().join("phantom-stderr");
    let mut phantom = phantom_command(project.path(), home.path())
        .args(["exec", "--", "sh", "-c", script])
        .env("READY", &ready)
        .env("MARKER", &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let child_pid: libc::pid_t = loop {
        if let Some(pid) = fs::read_to_string(&ready)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "child never started");
        std::thread::sleep(Duration::from_millis(20));
    };
    let phantom_pid = libc::pid_t::try_from(phantom.id()).unwrap();
    // SAFETY: signal the phantom process this test spawned.
    assert_eq!(unsafe { libc::kill(phantom_pid, libc::SIGTERM) }, 0);

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = phantom.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = phantom.kill();
            break phantom.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // SAFETY: best-effort cleanup of a child that outlived phantom.
    unsafe {
        libc::kill(child_pid, libc::SIGKILL);
    }
    let outcome = Outcome {
        code: status.code(),
        stderr: fs::read_to_string(&stderr_path).unwrap_or_default(),
        child_saw_term: marker.exists(),
    };
    drop((project, home));
    outcome
}

#[test]
fn sigterm_to_phantom_is_forwarded_and_the_child_status_propagates() {
    let outcome = exec_and_terminate_phantom(
        r#"trap 'echo term > "$MARKER"; exit 42' TERM; echo $$ > "$READY"; while :; do sleep 0.05; done"#,
    );
    assert_eq!(
        outcome.code,
        Some(42),
        "phantom must exit with the child's code, not die on SIGTERM\nstderr:\n{}",
        outcome.stderr
    );
    assert!(outcome.child_saw_term, "the child did not receive SIGTERM");
    assert!(
        outcome.stderr.contains("Shutting down proxy"),
        "stderr:\n{}",
        outcome.stderr
    );
}

#[test]
fn child_killed_by_forwarded_sigterm_exits_143() {
    let outcome = exec_and_terminate_phantom(r#"echo $$ > "$READY"; exec sleep 30"#);
    assert_eq!(outcome.code, Some(143), "stderr:\n{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("Shutting down proxy"),
        "stderr:\n{}",
        outcome.stderr
    );
}
