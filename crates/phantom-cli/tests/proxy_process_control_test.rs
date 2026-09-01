use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const VAULT_PASS: &str = "proxy-process-control-integration-passphrase";
const PROBE_PATH_ENV: &str = "PHANTOM_TEST_CHILD_ENV_PROBE";
const EXPECT_PROTECTED_ENV: &str = "PHANTOM_TEST_EXPECT_PROTECTED_TOKEN";

fn phantom_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_phantom"))
}

fn phantom_command(project: &Path, home: &Path) -> Command {
    let mut command = Command::new(phantom_binary());
    command
        .current_dir(project)
        .env("HOME", home)
        .env("USERPROFILE", home)
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

fn initialize(project: &Path, home: &Path) {
    fs::write(
        project.join(".env"),
        "OPENAI_API_KEY=sk-proxy-process-control-test-value\n",
    )
    .unwrap();
    let output = phantom_command(project, home)
        .args(["init", "--from", ".env"])
        .output()
        .unwrap();
    assert_success(&output, "phantom init");
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    predicate()
}

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

#[test]
fn detached_start_and_external_stop_fail_closed_without_touching_legacy_pid_state() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    initialize(project.path(), home.path());

    let daemon = phantom_command(project.path(), home.path())
        .args(["start", "--daemon"])
        .output()
        .unwrap();
    assert!(!daemon.status.success());
    assert!(String::from_utf8_lossy(&daemon.stderr).contains("Detached proxy mode is disabled"));
    assert!(!project.path().join(".phantom.pid").exists());

    let legacy_pid = project.path().join(".phantom.pid");
    fs::write(&legacy_pid, b"legacy-state-must-not-be-unlinked").unwrap();
    let stop = phantom_command(project.path(), home.path())
        .arg("stop")
        .output()
        .unwrap();
    assert!(!stop.status.success());
    assert!(String::from_utf8_lossy(&stop.stderr).contains("External proxy stop is disabled"));
    assert_eq!(
        fs::read(&legacy_pid).unwrap(),
        b"legacy-state-must-not-be-unlinked"
    );
}

#[test]
fn foreground_lock_allows_exactly_one_owner_without_a_pid_record() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    initialize(project.path(), home.path());

    let first = phantom_command(project.path(), home.path())
        .arg("start")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut guard = ChildGuard(Some(first));

    assert!(
        wait_until(Duration::from_secs(10), || {
            let status = phantom_command(project.path(), home.path())
                .args(["status", "--oneline"])
                .output()
                .unwrap();
            status.status.success()
                && String::from_utf8_lossy(&status.stdout).contains("foreground proxy active")
        }),
        "first start did not acquire the lifetime lock"
    );

    let second = phantom_command(project.path(), home.path())
        .arg("start")
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already owns"));
    assert!(
        !project.path().join(".phantom.pid").exists(),
        "foreground lifecycle must never persist a PID or bearer"
    );

    let mut first = guard.0.take().unwrap();
    first.kill().unwrap();
    first.wait().unwrap();
    assert!(wait_until(Duration::from_secs(5), || {
        let status = phantom_command(project.path(), home.path())
            .args(["status", "--oneline"])
            .output()
            .unwrap();
        status.status.success()
            && String::from_utf8_lossy(&status.stdout).contains("foreground proxy inactive")
    }));
}

#[test]
fn exec_child_does_not_receive_vault_passphrase_or_ambient_protected_value() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    initialize(project.path(), home.path());
    let probe = project.path().join("probe-complete");

    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_environment_probe", "--nocapture"])
        .env("OPENAI_API_KEY", "ambient-real-value-must-not-reach-child")
        .env(PROBE_PATH_ENV, &probe)
        .env(EXPECT_PROTECTED_ENV, "1")
        .output()
        .unwrap();
    assert_success(&output, "phantom exec protected child probe");
    assert!(probe.exists(), "child probe did not run");
}

#[test]
fn direct_child_does_not_receive_vault_passphrase() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let init = phantom_command(project.path(), home.path())
        .args(["init", "--empty"])
        .output()
        .unwrap();
    assert_success(&init, "phantom init --empty");
    let probe = project.path().join("direct-probe-complete");

    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_environment_probe", "--nocapture"])
        .env(PROBE_PATH_ENV, &probe)
        .output()
        .unwrap();
    assert_success(&output, "phantom exec direct child probe");
    assert!(probe.exists(), "direct child probe did not run");
}

#[test]
fn protected_connection_string_is_denied_before_vault_decryption() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgresql://example.invalid/app\n",
    )
    .unwrap();
    let init = phantom_command(project.path(), home.path())
        .args(["init", "--from", ".env"])
        .output()
        .unwrap();
    assert_success(&init, "phantom init connection string");

    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_environment_probe"])
        // If exec tried to open the file vault before applying the configured
        // connection-string denial, this deliberately wrong key would produce
        // a decryption error instead of the required policy error.
        .env("PHANTOM_VAULT_PASSPHRASE", "deliberately-wrong-passphrase")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Refusing to expose connection-string secret(s)"));
    assert!(!stderr.contains("decrypt"));
}

#[test]
fn child_environment_probe() {
    let Ok(path) = std::env::var(PROBE_PATH_ENV) else {
        return;
    };
    assert!(
        std::env::var_os("PHANTOM_VAULT_PASSPHRASE").is_none(),
        "vault passphrase reached delegated child"
    );
    if std::env::var_os(EXPECT_PROTECTED_ENV).is_some() {
        let value = std::env::var("OPENAI_API_KEY").expect("protected key session token");
        assert!(value.starts_with("phm_"), "protected key was not tokenized");
        assert_ne!(value, "ambient-real-value-must-not-reach-child");
    }
    fs::write(path, b"ok").unwrap();
}
