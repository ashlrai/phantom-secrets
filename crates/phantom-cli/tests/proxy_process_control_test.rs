use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const VAULT_PASS: &str = "proxy-process-control-integration-passphrase";

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

struct DaemonGuard {
    project: PathBuf,
    home: PathBuf,
    armed: bool,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = phantom_command(&self.project, &self.home)
            .arg("stop")
            .output();
        let pid_path = self.project.join(".phantom.pid");
        let _ = wait_until(Duration::from_secs(3), || !pid_path.exists());
    }
}

#[test]
fn daemon_acknowledgment_succeeds_and_daemon_unlinks_its_pid_file() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    initialize(project.path(), home.path());

    let start = phantom_command(project.path(), home.path())
        .args(["start", "--daemon"])
        .output()
        .unwrap();
    assert_success(&start, "phantom start --daemon");

    let pid_path = project.path().join(".phantom.pid");
    assert!(pid_path.exists(), "daemon did not publish its PID record");
    let mut guard = DaemonGuard {
        project: project.path().to_path_buf(),
        home: home.path().to_path_buf(),
        armed: true,
    };

    let stop = phantom_command(project.path(), home.path())
        .arg("stop")
        .output()
        .unwrap();
    assert_success(&stop, "phantom stop");
    assert!(
        String::from_utf8_lossy(&stop.stdout).contains("Authenticated proxy shutdown accepted"),
        "stop did not report authenticated acknowledgment"
    );
    assert!(
        wait_until(Duration::from_secs(5), || !pid_path.exists()),
        "daemon did not unlink its owned PID record after acknowledgment"
    );
    guard.armed = false;

    let status = phantom_command(project.path(), home.path())
        .args(["status", "--oneline"])
        .output()
        .unwrap();
    assert_success(&status, "phantom status --oneline");
    assert!(String::from_utf8_lossy(&status.stdout).contains("proxy off"));
}

#[test]
fn hostile_path_process_tools_are_never_executed_for_liveness() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    initialize(project.path(), home.path());

    let shims = project.path().join("hostile-path");
    fs::create_dir(&shims).unwrap();
    let marker = project.path().join("ambient-process-tool-ran");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["kill", "tasklist"] {
            let shim = shims.join(name);
            fs::write(
                &shim,
                format!("#!/bin/sh\nprintf ran > '{}'\nexit 0\n", marker.display()),
            )
            .unwrap();
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[cfg(windows)]
    for name in ["kill.cmd", "tasklist.cmd"] {
        fs::write(
            shims.join(name),
            format!("@echo ran>\"{}\"\r\n@exit /b 0\r\n", marker.display()),
        )
        .unwrap();
    }

    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let unused_port = listener.local_addr().unwrap().port();
    drop(listener);
    fs::write(
        project.path().join(".phantom.pid"),
        format!("{}:{unused_port}:{}", std::process::id(), "a".repeat(64)),
    )
    .unwrap();

    let output = phantom_command(project.path(), home.path())
        .args(["status", "--oneline"])
        .env("PATH", &shims)
        .output()
        .unwrap();
    assert_success(&output, "phantom status with hostile PATH");
    assert!(String::from_utf8_lossy(&output.stdout).contains("proxy unknown"));
    assert!(
        !marker.exists(),
        "an ambient process-control executable was launched"
    );
}
