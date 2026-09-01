use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Barrier};
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

struct StartChildrenGuard {
    project: PathBuf,
    home: PathBuf,
    children: Vec<Child>,
    armed: bool,
}

impl Drop for StartChildrenGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = phantom_command(&self.project, &self.home)
            .arg("stop")
            .output();
        for child in &mut self.children {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
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
fn concurrent_starts_publish_exactly_one_live_proxy_owner() {
    let project = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    initialize(project.path(), home.path());

    let barrier = Arc::new(Barrier::new(3));
    let mut launchers = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let project = project.path().to_path_buf();
        let home = home.path().to_path_buf();
        launchers.push(std::thread::spawn(move || {
            barrier.wait();
            phantom_command(&project, &home)
                .arg("start")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn concurrent phantom start")
        }));
    }
    barrier.wait();

    let children = launchers
        .into_iter()
        .map(|launcher| launcher.join().expect("join start launcher"))
        .collect();
    let mut guard = StartChildrenGuard {
        project: project.path().to_path_buf(),
        home: home.path().to_path_buf(),
        children,
        armed: true,
    };

    let pid_path = project.path().join(".phantom.pid");
    assert!(
        wait_until(Duration::from_secs(10), || pid_path.exists()),
        "concurrent starts did not publish a PID record"
    );
    assert!(
        wait_until(Duration::from_secs(10), || {
            guard
                .children
                .iter_mut()
                .map(|child| child.try_wait().expect("poll start child"))
                .filter(Option::is_some)
                .count()
                == 1
        }),
        "exactly one concurrent start must remain as the live proxy owner"
    );

    let live_child_pids: Vec<_> = guard
        .children
        .iter_mut()
        .filter_map(|child| {
            child
                .try_wait()
                .expect("poll start child")
                .is_none()
                .then_some(child.id())
        })
        .collect();
    assert_eq!(live_child_pids.len(), 1, "more than one proxy stayed live");
    let published_pid: u32 = fs::read_to_string(&pid_path)
        .expect("read PID record")
        .split(':')
        .next()
        .expect("PID field")
        .parse()
        .expect("numeric PID");
    assert_eq!(
        published_pid, live_child_pids[0],
        "PID record was not owned by the only live proxy"
    );

    let stop = phantom_command(project.path(), home.path())
        .arg("stop")
        .output()
        .unwrap();
    assert_success(&stop, "stop concurrent-start winner");
    assert!(
        wait_until(Duration::from_secs(5), || !pid_path.exists()),
        "live owner did not unlink its PID record"
    );
    assert!(
        wait_until(Duration::from_secs(5), || guard.children.iter_mut().all(
            |child| child.try_wait().expect("poll stopped child").is_some()
        )),
        "a concurrent start remained orphaned after stopping the published owner"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !pid_path.exists(),
        "a losing start overwrote the PID record after shutdown"
    );
    guard.armed = false;
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
