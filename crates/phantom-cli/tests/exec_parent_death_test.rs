//! A killed launcher or Phantom must not leave the exec process tree running.
#![cfg(unix)]

mod common;

use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(15);
const TREE_SCRIPT: &str = r#"
trap '' TERM HUP
sleep 300 &
printf '%s\n' "$!" > "$GRANDCHILD"
printf '%s\n' "${PHANTOM_PROXY_PORT-0}" > "$PORT"
printf '%s\n' "$$" > "$READY"
wait
"#;

struct Fixture {
    project: tempfile::TempDir,
    home: tempfile::TempDir,
    processes: Vec<Child>,
    cleanup_pids: Vec<libc::pid_t>,
}

impl Fixture {
    fn new(proxied: bool) -> Self {
        let fixture = Self {
            project: common::canonical_tempdir(),
            home: common::canonical_tempdir(),
            processes: Vec::new(),
            cleanup_pids: Vec::new(),
        };
        if proxied {
            fs::write(
                fixture.path(".env"),
                "OPENAI_API_KEY=sk-parent-death-test-synthetic-value\n",
            )
            .unwrap();
            let output = fixture
                .phantom()
                .args(["init", "--from", ".env"])
                .output()
                .unwrap();
            assert!(output.status.success(), "initialize synthetic test project");
        } else {
            let config = phantom_core::config::PhantomConfig::new_with_defaults(
                fixture
                    .project
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
            fs::write(
                fixture.path(".phantom.toml"),
                toml::to_string_pretty(&config).unwrap(),
            )
            .unwrap();
            fs::write(fixture.path(".env"), "PORT=3000\n").unwrap();
        }
        fixture
    }

    fn path(&self, name: &str) -> PathBuf {
        self.project.path().join(name)
    }

    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        // These tests must not consume ambient credentials or inherit an exec
        // marker from the runner. All stored values are synthetic fixtures.
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("NO_COLOR", "1")
            .env(
                "PHANTOM_VAULT_PASSPHRASE",
                "parent-death-test-only-unlock-phrase",
            )
            .current_dir(self.project.path());
        command
    }

    fn phantom(&self) -> Command {
        self.command(env!("CARGO_BIN_EXE_phantom"))
    }

    fn spawn(&mut self, mut command: Command) -> libc::pid_t {
        command
            .env("READY", self.path("ready"))
            .env("GRANDCHILD", self.path("grandchild"))
            .env("PORT", self.path("port"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(self.path("stderr")).unwrap());
        let child = command.spawn().unwrap();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        self.processes.push(child);
        pid
    }

    fn start_phantom(&mut self, script: &str) -> libc::pid_t {
        let mut command = self.phantom();
        command.args(["exec", "--", "sh", "-c", script]);
        self.spawn(command)
    }

    fn ready_pid(&mut self, name: &str) -> libc::pid_t {
        let path = self.path(name);
        eventually(&format!("{name} PID file"), || read_pid(&path).is_some());
        let pid = read_pid(&path).unwrap();
        assert!(pid > 1);
        self.cleanup_pids.push(pid);
        pid
    }

    fn port(&self) -> u16 {
        fs::read_to_string(self.path("port"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn wait(&mut self, index: usize) -> ExitStatus {
        let mut status = None;
        eventually("owned process exit", || {
            status = self.processes[index].try_wait().unwrap();
            status.is_some()
        });
        status.unwrap()
    }

    fn remember_children(&mut self, parent: libc::pid_t) -> Vec<libc::pid_t> {
        let children = child_pids(parent);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(
            children.len() >= 2,
            "ready Phantom must own both its command and independent guardian"
        );
        self.cleanup_pids.extend(children.iter().copied());
        children
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Also recover PIDs if a readiness assertion panicked before registering
        // them. A broken lifecycle implementation must not leak test sleepers.
        for name in ["phantom-pid", "ready", "grandchild"] {
            if let Some(pid) = read_pid(&self.path(name)) {
                self.cleanup_pids.push(pid);
            }
        }
        for child in &mut self.processes {
            let _ = child.kill();
        }
        for &pid in &self.cleanup_pids {
            if pid > 1 && running(pid) {
                // SAFETY: these PIDs came from this fixture's process handles
                // or private files; never signal the runner's process group.
                unsafe {
                    if libc::getpgid(pid) == pid {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        for child in &mut self.processes {
            let _ = child.wait();
        }
    }
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn eventually(description: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn signal(pid: libc::pid_t, signal: libc::c_int) {
    assert!(pid > 1);
    // SAFETY: the fixture owns this live process.
    assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
}

fn running(pid: libc::pid_t) -> bool {
    // SAFETY: signal zero only checks process existence and permissions.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
    }
    process_state(pid) != Some('Z')
}

#[cfg(target_os = "macos")]
fn process_state(pid: libc::pid_t) -> Option<char> {
    // SAFETY: the buffer has the exact size and layout required by libproc.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as libc::c_int;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    (read == size).then_some(match info.pbi_status {
        libc::SZOMB => 'Z',
        libc::SSTOP => 'T',
        _ => 'R',
    })
}

#[cfg(target_os = "linux")]
fn process_state(pid: libc::pid_t) -> Option<char> {
    // A Linux container's init need not promptly reap orphaned zombies, which
    // have exited and cannot hold listeners or execute more work.
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            stat.rsplit_once(") ")
                .and_then(|(_, tail)| tail.chars().next())
        })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_state(_: libc::pid_t) -> Option<char> {
    None
}

#[cfg(target_os = "macos")]
fn child_pids(parent: libc::pid_t) -> Vec<libc::pid_t> {
    let mut children = vec![0; 64];
    // SAFETY: libproc receives a properly aligned writable PID buffer.
    let count = unsafe {
        libc::proc_listchildpids(
            parent,
            children.as_mut_ptr().cast(),
            std::mem::size_of_val(children.as_slice()) as libc::c_int,
        )
    };
    assert!(count >= 0, "list supervised children");
    // Unlike proc_listpids, proc_listchildpids returns a PID count, while
    // accepting the buffer capacity in bytes.
    children.truncate(count as usize);
    children.retain(|&pid| pid > 1);
    children
}

#[cfg(target_os = "linux")]
fn child_pids(parent: libc::pid_t) -> Vec<libc::pid_t> {
    // Linux records children under the thread that created them. Phantom's
    // run wrapper uses a worker thread, so examining only its main TID misses
    // the guardian and command even though both belong to this process.
    let mut children = Vec::new();
    for thread in fs::read_dir(format!("/proc/{parent}/task")).unwrap() {
        let path = thread.unwrap().path().join("children");
        // Runtime threads may finish between the directory scan and the read.
        match fs::read_to_string(path) {
            Ok(pids) => children.extend(
                pids.split_whitespace()
                    .map(|pid| pid.parse::<libc::pid_t>().unwrap()),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read supervised child PIDs: {error}"),
        }
    }
    children.sort_unstable();
    children.dedup();
    children
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn child_pids(_: libc::pid_t) -> Vec<libc::pid_t> {
    Vec::new()
}

fn assert_stopped(pids: &[libc::pid_t]) {
    eventually("all supervised processes to exit", || {
        pids.iter().all(|&pid| !running(pid))
    });
}

fn port_open(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok()
}

#[test]
fn sigkill_of_phantom_stops_children_grandchildren_and_proxy() {
    for proxied in [false, true] {
        let mut fixture = Fixture::new(proxied);
        let phantom = fixture.start_phantom(TREE_SCRIPT);
        let child = fixture.ready_pid("ready");
        let grandchild = fixture.ready_pid("grandchild");
        let mut supervised = fixture.remember_children(phantom);
        supervised.extend([child, grandchild]);
        let port = fixture.port();
        assert_eq!(port != 0, proxied);
        if proxied {
            assert!(
                port_open(port),
                "proxy must start before its owner is killed"
            );
        }

        signal(phantom, libc::SIGKILL);
        fixture.wait(0);
        assert_stopped(&supervised);
        if proxied {
            eventually("proxy listener closure", || !port_open(port));
        }
    }
}

#[test]
fn sigkill_of_launcher_stops_phantom_and_its_process_tree() {
    for (proxied, stop_phantom) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut fixture = Fixture::new(proxied);
        let mut launcher = fixture.command("sh");
        launcher
            .args([
                "-c",
                r#""$PHANTOM_BINARY" exec -- sh -c "$CHILD_SCRIPT" & echo $! > "$PHANTOM_PID"; wait"#,
            ])
            .env("PHANTOM_BINARY", env!("CARGO_BIN_EXE_phantom"))
            .env("CHILD_SCRIPT", TREE_SCRIPT)
            .env("PHANTOM_PID", fixture.path("phantom-pid"));
        let launcher = fixture.spawn(launcher);
        let phantom = fixture.ready_pid("phantom-pid");
        let child = fixture.ready_pid("ready");
        let grandchild = fixture.ready_pid("grandchild");
        let mut supervised = fixture.remember_children(phantom);
        supervised.extend([phantom, child, grandchild]);
        let port = fixture.port();
        assert_eq!(port != 0, proxied);

        if stop_phantom {
            signal(phantom, libc::SIGSTOP);
            eventually("Phantom to stop before its launcher dies", || {
                process_state(phantom) == Some('T')
            });
        }
        signal(launcher, libc::SIGKILL);
        fixture.wait(0);
        assert_stopped(&supervised);
        if proxied {
            eventually("orphaned proxy listener closure", || !port_open(port));
        }
    }
}

#[test]
fn normal_child_exit_reaps_background_descendants_and_preserves_status() {
    for proxied in [false, true] {
        let mut fixture = Fixture::new(proxied);
        fixture
            .start_phantom(r#"sleep 300 & echo $! > "$GRANDCHILD"; echo $$ > "$READY"; exit 23"#);
        let grandchild = fixture.ready_pid("grandchild");
        assert_eq!(fixture.wait(0).code(), Some(23));
        assert_stopped(&[grandchild]);
    }
}

#[test]
fn direct_exec_forwards_signals_and_preserves_child_status() {
    let mut fixture = Fixture::new(false);
    let phantom = fixture
        .start_phantom(r#"trap 'exit 42' TERM; echo $$ > "$READY"; while :; do sleep 0.05; done"#);
    fixture.ready_pid("ready");
    signal(phantom, libc::SIGTERM);
    assert_eq!(fixture.wait(0).code(), Some(42));
}

#[test]
fn recursive_exec_is_refused_directly_and_through_a_shell() {
    for proxied in [false, true] {
        for via_shell in [false, true] {
            let mut fixture = Fixture::new(proxied);
            let mut command = fixture.phantom();
            command.args(["exec", "--"]);
            if via_shell {
                command
                    .args([
                        "sh",
                        "-c",
                        r#"exec "$PHANTOM_BINARY" exec -- touch "$SENTINEL""#,
                    ])
                    .env("PHANTOM_BINARY", env!("CARGO_BIN_EXE_phantom"));
            } else {
                command
                    .arg(env!("CARGO_BIN_EXE_phantom"))
                    .args(["exec", "--", "touch"])
                    .arg(fixture.path("sentinel"));
            }
            command.env("SENTINEL", fixture.path("sentinel"));
            fixture.spawn(command);
            assert!(!fixture.wait(0).success(), "nested exec must fail closed");
            assert!(!fixture.path("sentinel").exists());
            let stderr = fs::read_to_string(fixture.path("stderr")).unwrap();
            assert!(
                stderr.contains("PHANTOM_EXEC_ACTIVE")
                    || stderr.contains("recursive")
                    || stderr.contains("nested"),
                "nested launch must explain the recursion guard"
            );
        }
    }
}

#[test]
fn exec_marker_is_presence_based_and_checked_before_project_access() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new(false);
    fs::remove_file(fixture.path(".phantom.toml")).unwrap();
    for marker in [
        std::ffi::OsString::new(),
        std::ffi::OsString::from_vec(vec![0xff]),
    ] {
        let output = fixture
            .phantom()
            .env("PHANTOM_EXEC_ACTIVE", marker)
            .args(["exec", "--", "touch"])
            .arg(fixture.path("sentinel"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!fixture.path("sentinel").exists());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("No .phantom.toml"),
            "guard must run before project access"
        );
    }
    let version = fixture
        .phantom()
        .env("PHANTOM_EXEC_ACTIVE", "1")
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "informational commands remain usable"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn interactive_child_reads_terminal_and_foreground_returns_to_launcher() {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;

    for kill_phantom in [false, true] {
        let mut fixture = Fixture::new(true);
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: openpty initializes both output descriptors; no termios or
        // window-size override is requested here.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0,
            "allocate test terminal"
        );
        let mut master = unsafe { fs::File::from_raw_fd(master) };
        let slave = unsafe { fs::File::from_raw_fd(slave) };
        for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                -1
            );
        }
        let mut attributes = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut attributes) },
            0
        );
        // TOSTOP catches Phantom writing progress before reclaiming foreground.
        // Disable input echo; Phantom's progress still exercises tty writes.
        attributes.c_lflag |= libc::TOSTOP;
        attributes.c_lflag &= !libc::ECHO;
        assert_eq!(
            unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &attributes) },
            0
        );

        let mut launcher = fixture.command("sh");
        launcher
            .args([
                "-c",
                r#"
"$PHANTOM_BINARY" exec -- sh -c "$CHILD_SCRIPT" < /dev/tty &
phantom=$!
printf '%s\n' "$phantom" > "$PHANTOM_PID"
wait "$phantom" 2>/dev/null
status=$?
while [ ! -f "$LAUNCHER_READ" ]; do sleep 0.02; done
IFS= read -r answer || exit 95
[ "$answer" = launcher-input ] || exit 96
printf '%s\n' "$status" > "$LAUNCHER_DONE"
"#,
            ])
            .env("PHANTOM_BINARY", env!("CARGO_BIN_EXE_phantom"))
            .env("PHANTOM_PID", fixture.path("phantom-pid"))
            .env("READY", fixture.path("ready"))
            .env("CHILD_READ", fixture.path("child-read"))
            .env("LAUNCHER_READ", fixture.path("launcher-read"))
            .env("LAUNCHER_DONE", fixture.path("launcher-done"))
            .env(
                "CHILD_SCRIPT",
                r#"
printf '%s\n' "$$" > "$READY"
IFS= read -r answer || exit 91
[ "$answer" = child-input ] || exit 92
: > "$CHILD_READ"
IFS= read -r answer || exit 93
[ "$answer" = child-exit ] || exit 94
"#,
            )
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        // SAFETY: only async-signal-safe syscalls execute after fork. The
        // launcher owns a fresh session and uses this PTY as its controlling tty.
        unsafe {
            launcher.pre_exec(|| {
                if libc::setsid() < 0
                    || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) < 0
                    || libc::tcsetpgrp(libc::STDIN_FILENO, libc::getpgrp()) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        fixture.processes.push(launcher.spawn().unwrap());
        let phantom = fixture.ready_pid("phantom-pid");
        let child = fixture.ready_pid("ready");
        let supervised = fixture.remember_children(phantom);
        signal(child, libc::SIGSTOP);
        eventually("Phantom to relay the child's job-control stop", || {
            process_state(phantom) == Some('T') && process_state(child) == Some('T')
        });
        signal(phantom, libc::SIGCONT);
        master.write_all(b"child-input\n").unwrap();
        eventually("child terminal read", || {
            fixture.path("child-read").exists()
        });

        if kill_phantom {
            signal(phantom, libc::SIGKILL);
        } else {
            master.write_all(b"child-exit\n").unwrap();
        }
        assert_stopped(&supervised);
        assert_stopped(&[phantom, child]);
        // Let the launcher read only once the guardian has finished restoring
        // the tty. Reading while in a background group would stop it with
        // SIGTTIN, so completion proves foreground ownership was returned.
        fs::write(fixture.path("launcher-read"), "").unwrap();
        master.write_all(b"launcher-input\n").unwrap();
        let mut status = None;
        eventually("launcher terminal read after exec", || {
            // Opening the file precedes printf's write; wait for a complete
            // integer rather than mistaking an empty file for readiness.
            status = fs::read_to_string(fixture.path("launcher-done"))
                .ok()
                .and_then(|text| text.trim().parse::<i32>().ok());
            status.is_some()
        });
        let status = status.unwrap();
        if kill_phantom {
            assert_eq!(status, 128 + libc::SIGKILL);
        } else {
            assert_eq!(status, 0, "interactive child must finish successfully");
        }
        // macOS waits for pending tty output while its session leader exits.
        // Drain output without printing it or replacing the slave stderr that
        // makes the TOSTOP assertion meaningful.
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        assert_ne!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1
        );
        let mut launcher_status = None;
        let mut discarded = [0; 4096];
        eventually("launcher exit after draining its terminal output", || {
            for _ in 0..32 {
                match master.read(&mut discarded) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    // Linux reports EIO when the slave side closes.
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("drain test terminal: {error}"),
                }
            }
            launcher_status = fixture.processes[0].try_wait().unwrap();
            launcher_status.is_some()
        });
        assert!(launcher_status.unwrap().success());
    }
}
