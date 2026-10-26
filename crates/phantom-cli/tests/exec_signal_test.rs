//! `phantom exec` must not die on SIGTERM and orphan its child: it forwards
//! the signal, waits for the child, shuts the proxy down, and exits with the
//! child's status.
#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const VAULT_PASS: &str = "exec-signal-integration-unlock-phrase";

fn phantom_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_phantom"))
}

fn phantom_command(project: &Path, home: &Path) -> Command {
    with_test_env(Command::new(phantom_binary()), project, home)
}

fn with_test_env(mut command: Command, project: &Path, home: &Path) -> Command {
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

/// What happened after a signal was sent to phantom.
struct Outcome {
    /// phantom's exit code; `None` if a signal killed it.
    code: Option<i32>,
    stderr: String,
    child_saw_term: bool,
}

/// How the test starts phantom and whom it signals.
struct Run<'a> {
    /// The child's `sh -c` script; it must write `$$` to `$READY`.
    script: &'a str,
    signal: libc::c_int,
    /// Start phantom with SIGHUP already ignored, as `nohup` does.
    inherit_ignored_hangup: bool,
    /// Also send the signal to the child directly.
    signal_child_too: bool,
}

/// Send SIGTERM to phantom only.
fn exec_and_terminate_phantom(script: &str) -> Outcome {
    exec_and_signal(Run {
        script,
        signal: libc::SIGTERM,
        inherit_ignored_hangup: false,
        signal_child_too: false,
    })
}

/// Start `phantom exec -- sh -c <script>`, wait for the child to write its
/// pid to `$READY`, send the signal, and wait (bounded) for phantom to exit.
/// The child is killed afterwards if it outlived phantom, so a regression
/// fails the test instead of leaking an orphan.
fn exec_and_signal(run: Run<'_>) -> Outcome {
    let (project, home) = initialized_project();
    let ready = project.path().join("ready");
    let marker = project.path().join("child-saw-term");
    let stderr_path = project.path().join("phantom-stderr");
    let mut command = if run.inherit_ignored_hangup {
        // `exec` keeps the pid, so the process the test signals is phantom,
        // started with SIGHUP ignored.
        let mut wrapper = Command::new("sh");
        wrapper
            .arg("-c")
            .arg(r#"trap '' HUP; exec "$0" "$@""#)
            .arg(phantom_binary());
        with_test_env(wrapper, project.path(), home.path())
    } else {
        phantom_command(project.path(), home.path())
    };
    command.args(["exec", "--", "sh", "-c", run.script]);
    let mut phantom = command
        .env("READY", &ready)
        .env("MARKER", &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    let child_pid: libc::pid_t = common::poll(Duration::from_secs(30), || {
        fs::read_to_string(&ready)
            .ok()
            .and_then(|text| text.trim().parse().ok())
    })
    .expect("child never started");
    let phantom_pid = libc::pid_t::try_from(phantom.id()).unwrap();
    // SAFETY: signal the phantom process (and its child) this test spawned.
    assert_eq!(unsafe { libc::kill(phantom_pid, run.signal) }, 0);
    if run.signal_child_too {
        assert_eq!(unsafe { libc::kill(child_pid, run.signal) }, 0);
    }

    let status = common::poll(Duration::from_secs(30), || phantom.try_wait().unwrap())
        .unwrap_or_else(|| {
            let _ = phantom.kill();
            phantom.wait().unwrap()
        });
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

/// `nohup phantom exec ...` (or a script's `&` job) starts phantom with
/// SIGHUP ignored. Installing a handler for it would reset the child's
/// disposition to the default on exec, so a hangup would kill the child.
/// Phantom must leave an inherited ignore alone: the child survives SIGHUP
/// (sent to both) and its own exit code comes through.
#[test]
fn inherited_ignored_sighup_stays_ignored_for_the_child() {
    let outcome = exec_and_signal(Run {
        script: r#"echo $$ > "$READY"; i=0; while [ $i -lt 30 ]; do sleep 0.05; i=$((i+1)); done; exit 7"#,
        signal: libc::SIGHUP,
        inherit_ignored_hangup: true,
        signal_child_too: true,
    });
    assert_eq!(
        outcome.code,
        Some(7),
        "the child must survive SIGHUP it inherited as ignored\nstderr:\n{}",
        outcome.stderr
    );
}
