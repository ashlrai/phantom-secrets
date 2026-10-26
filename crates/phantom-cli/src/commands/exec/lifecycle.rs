//! Unix exec ownership. The guardian is forked before the runtime or vault is
//! opened and uses only async-signal-safe libc calls in the fork child.
//!
//! A CLOEXEC lifeline remains open only in Phantom. The child's pre-exec hook
//! registers its group before closing its copy, so even SIGKILL during spawn
//! cannot leave an unregistered running child. EOF kills the entire group.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::mpsc;

pub struct Lifecycle {
    writer: Option<OwnedFd>,
    guardian: Option<libc::pid_t>,
    stop: Option<mpsc::Sender<()>>,
    monitor: Option<std::thread::JoinHandle<()>>,
    terminal: Option<std::fs::File>,
}

impl Lifecycle {
    pub fn new() -> io::Result<Self> {
        // Capture the launcher before starting any asynchronous work. A change
        // means reparenting, including launchers reaped by a Linux subreaper.
        let parent = unsafe { libc::getppid() };
        let phantom = unsafe { libc::getpid() };
        let terminal = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()
            .filter(|file| unsafe { libc::tcgetpgrp(file.as_raw_fd()) == libc::getpgrp() });
        let tty = terminal.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let foreground = unsafe { libc::getpgrp() };
        let mut fds = [-1; 2];
        // SAFETY: valid output buffer; both descriptors are immediately owned.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        for fd in &fds {
            if unsafe { libc::fcntl(*fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        // Block signals across fork so a terminal signal cannot kill the
        // guardian before it detaches from Phantom's foreground group.
        let mut blocked = unsafe { std::mem::zeroed() };
        let mut previous = unsafe { std::mem::zeroed() };
        unsafe { libc::sigfillset(&mut blocked) };
        let error = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        let guardian = unsafe { libc::fork() };
        let fork_error = io::Error::last_os_error();
        if guardian == 0 {
            // Do not allocate, log, unwind, access the vault, or invoke Rust
            // destructors here: other threads existed at fork (main's wrapper).
            unsafe {
                libc::close(writer.as_raw_fd());
                // Keep the controlling terminal's session so cleanup can
                // restore its foreground group, but leave the signal group.
                if libc::setpgid(0, 0) != 0 {
                    libc::_exit(125);
                }
                for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGTTOU] {
                    libc::signal(signal, libc::SIG_IGN);
                }
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
                // Never hold the caller's stdout/stderr pipes open.
                for fd in 0..=2 {
                    if fd != reader.as_raw_fd() && fd != tty {
                        libc::close(fd);
                    }
                }
                guardian_loop(reader.as_raw_fd(), tty, foreground, phantom, parent);
            }
        }
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
        if guardian < 0 {
            return Err(fork_error);
        }
        drop(reader);
        let mut guard = Self {
            writer: Some(writer),
            guardian: Some(guardian),
            stop: None,
            monitor: None,
            terminal,
        };
        let (stop, stopped) = mpsc::channel();
        guard.stop = Some(stop);
        guard.monitor = Some(
            std::thread::Builder::new()
                .name("phantom-parent".into())
                .spawn(move || {
                    while let Err(mpsc::RecvTimeoutError::Timeout) =
                        stopped.recv_timeout(std::time::Duration::from_millis(100))
                    {
                        if unsafe { libc::getppid() } != parent {
                            // Closing every descriptor ends the proxy and releases the
                            // lifeline. The independent guardian cleans up descendants.
                            unsafe { libc::_exit(125) };
                        }
                    }
                })?,
        );
        Ok(guard)
    }

    pub fn configure(&self, command: &mut tokio::process::Command) {
        let writer = self
            .writer
            .as_ref()
            .expect("live exec guardian")
            .as_raw_fd();
        let parent = unsafe { libc::getpid() };
        let tty = self.terminal.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        // SAFETY: the closure uses only async-signal-safe syscalls. Registration
        // is a single atomic pipe write; no child program starts before it.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let group = libc::getpid();
                let size = std::mem::size_of_val(&group);
                loop {
                    let written = libc::write(writer, (&group as *const libc::pid_t).cast(), size);
                    if written == size as isize {
                        break;
                    }
                    let error = io::Error::last_os_error();
                    if written < 0 && error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                libc::close(writer);
                if libc::getppid() != parent {
                    libc::kill(-group, libc::SIGKILL);
                    libc::_exit(125);
                }
                if tty >= 0 {
                    let mut blocked = std::mem::zeroed();
                    let mut previous = std::mem::zeroed();
                    libc::sigemptyset(&mut blocked);
                    libc::sigaddset(&mut blocked, libc::SIGTTOU);
                    let error = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous);
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(error));
                    }
                    let result = libc::tcsetpgrp(tty, group);
                    let error = io::Error::last_os_error();
                    libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
                    if result != 0 {
                        return Err(error);
                    }
                }
                Ok(())
            });
        }
        command.kill_on_drop(true);
    }

    pub fn finish(&mut self) {
        self.writer.take();
        if let Some(guardian) = self.guardian.take() {
            // Also restore terminal ownership before Phantom writes output
            // (a terminal with TOSTOP set stops background writers).
            loop {
                let result = unsafe { libc::waitpid(guardian, std::ptr::null_mut(), 0) };
                if result >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
    }

    /// Ctrl-Z now reaches the child's foreground group. Relay its stop to
    /// Phantom so the launching shell still observes a stopped job, and hand
    /// the terminal back to the child when the shell resumes Phantom.
    pub async fn relay_job_control(&self, child: Option<u32>) {
        let Some(terminal) = self.terminal.as_ref() else {
            return std::future::pending().await;
        };
        let Some(child) = child else {
            return std::future::pending().await;
        };
        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            ticks.tick().await;
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // WSTOPPED without WEXITED cannot reap the child out from under
            // Tokio. WNOWAIT leaves ownership of all statuses with its waiter.
            let stopped = unsafe {
                libc::waitid(
                    libc::P_PID,
                    child as libc::id_t,
                    &mut info,
                    libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
                ) == 0
                    && info.si_pid() != 0
            };
            if !stopped {
                continue;
            }
            let tty = terminal.as_raw_fd();
            // SAFETY: block SIGTTOU only on this thread around tty ownership
            // changes. SIGSTOP stops the process, not just this Tokio worker.
            unsafe {
                let mut blocked = std::mem::zeroed();
                let mut previous = std::mem::zeroed();
                libc::sigemptyset(&mut blocked);
                libc::sigaddset(&mut blocked, libc::SIGTTOU);
                if libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) != 0 {
                    continue;
                }
                let group = libc::getpgrp();
                if libc::tcgetpgrp(tty) == child as libc::pid_t {
                    libc::tcsetpgrp(tty, group);
                }
                // Thread-directed delivery is essential: process-directed
                // kill could stop another worker after this one has already
                // continued the child, leaving only Phantom suspended.
                libc::raise(libc::SIGSTOP);
                // A shell's `bg` resumes the job without giving it foreground.
                // Leave it in the background in that case, like a normal job.
                if libc::tcgetpgrp(tty) == group {
                    libc::tcsetpgrp(tty, child as libc::pid_t);
                }
                libc::kill(-(child as libc::pid_t), libc::SIGCONT);
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            }
        }
    }
}

impl Drop for Lifecycle {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(monitor) = self.monitor.take() {
            let _ = monitor.join();
        }
        self.finish();
    }
}

unsafe fn guardian_loop(
    reader: libc::c_int,
    tty: libc::c_int,
    foreground: libc::pid_t,
    phantom: libc::pid_t,
    launcher: libc::pid_t,
) -> ! {
    let mut group: libc::pid_t = 0;
    let mut received = 0;
    let size = std::mem::size_of_val(&group);
    loop {
        let mut event = libc::pollfd {
            fd: reader,
            events: libc::POLLIN,
            revents: 0,
        };
        let polled = libc::poll(&mut event, 1, 100);
        if polled == 0 {
            // A stopped Phantom cannot run its own parent monitor. This
            // fallback still removes it when its launcher has been reaped.
            // Check our parent too, so a recycled Phantom PID is never used.
            if libc::getppid() == phantom
                && libc::kill(launcher, 0) != 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                libc::kill(phantom, libc::SIGKILL);
            }
            continue;
        }
        if polled < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let mut byte = 0u8;
        let result = libc::read(reader, (&mut byte as *mut u8).cast(), 1);
        if result == 0 {
            break;
        }
        if result < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        if received < size {
            (&mut group as *mut libc::pid_t)
                .cast::<u8>()
                .add(received)
                .write(byte);
            received += 1;
        }
    }
    if received == size && group > 0 {
        libc::kill(-group, libc::SIGKILL);
    }
    if tty >= 0 && libc::tcgetpgrp(tty) == group {
        libc::tcsetpgrp(tty, foreground);
    }
    libc::_exit(0);
}
