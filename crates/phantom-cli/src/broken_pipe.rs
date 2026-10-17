//! A closed stdout is a normal end, not a crash.
//!
//! `phantom list | head` closes the pipe once `head` has its lines. Rust
//! ignores SIGPIPE, so the next write to stdout fails with EPIPE: `println!`
//! then panics ("failed printing to stdout: Broken pipe"), which used to end
//! the process with exit 101 and a panic message, and an explicit `write!`
//! returned the error, which `main` printed as a failure.
//!
//! Both are recognised here and turned into a quiet exit with
//! [`BROKEN_PIPE_EXIT`]. The SIGPIPE disposition itself is left alone: making
//! it fatal again would also make a write to a closed socket kill the proxy
//! that `phantom exec` runs in-process, and would change what `exec` passes
//! on to the command it starts. Only stdout counts: a broken pipe to a child
//! process or a socket is still an error.

use std::any::Any;
use std::io;

/// Exit status after the reader of stdout went away: 128 + SIGPIPE (13), what
/// a shell reports for a command SIGPIPE ended, so `set -o pipefail` scripts
/// see the same status they would for any other Unix tool.
pub const BROKEN_PIPE_EXIT: i32 = 141;

/// The prefix std puts on the panic a failed `print!`/`println!` raises.
const STDOUT_PRINT_PANIC: &str = "failed printing to stdout: ";

/// OS errors that mean "the reader of this pipe is gone", as std reports them.
fn broken_pipe_os_errors() -> Vec<io::Error> {
    #[cfg(unix)]
    {
        vec![io::Error::from_raw_os_error(libc::EPIPE)]
    }
    #[cfg(windows)]
    {
        // ERROR_NO_DATA ("The pipe is being closed") is what a write to a
        // pipe whose reader closed fails with; ERROR_BROKEN_PIPE is its peer.
        vec![
            io::Error::from_raw_os_error(232),
            io::Error::from_raw_os_error(109),
        ]
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

/// Whether a panic payload is std's "failed printing to stdout" panic for a
/// broken pipe. The OS error text is built from the same error std formats,
/// so it does not depend on the platform's wording.
pub fn is_stdout_broken_pipe_panic(payload: &(dyn Any + Send)) -> bool {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied());
    let Some(detail) = message.and_then(|m| m.strip_prefix(STDOUT_PRINT_PANIC)) else {
        return false;
    };
    broken_pipe_os_errors()
        .iter()
        .any(|error| detail == error.to_string())
}

/// Whether `error` is a write to stdout that failed because its reader went
/// away: a broken-pipe I/O error in the chain, and stdout itself closed. The
/// second check keeps a broken pipe to anything else a real error.
pub fn is_stdout_broken_pipe_error(error: &anyhow::Error) -> bool {
    let broken_pipe = error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_error| io_error.kind() == io::ErrorKind::BrokenPipe)
    });
    broken_pipe && stdout_reader_gone()
}

/// Whether nothing reads stdout any more.
#[cfg(unix)]
fn stdout_reader_gone() -> bool {
    let mut descriptor = libc::pollfd {
        fd: libc::STDOUT_FILENO,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: one valid pollfd, a zero timeout; poll only reports state.
    let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
    ready > 0 && descriptor.revents & (libc::POLLERR | libc::POLLHUP) != 0
}

/// Windows has no cheap way to ask; a write that failed with a broken pipe
/// error there is taken at its word.
#[cfg(not(unix))]
fn stdout_reader_gone() -> bool {
    true
}

/// Keep the default panic report for every panic except the stdout broken
/// pipe one, which `main` turns into a quiet exit after the worker thread has
/// unwound (so destructors, including zeroizing ones, still run).
pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if !is_stdout_broken_pipe_panic(info.payload()) {
            default_hook(info);
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panic_text(detail: &str) -> Box<dyn Any + Send> {
        Box::new(format!("{STDOUT_PRINT_PANIC}{detail}"))
    }

    #[test]
    fn recognises_the_stdout_broken_pipe_panic() {
        for error in broken_pipe_os_errors() {
            assert!(is_stdout_broken_pipe_panic(&*panic_text(
                &error.to_string()
            )));
        }
    }

    #[test]
    fn ignores_other_panics() {
        let other_os_error = io::Error::from_raw_os_error(5).to_string();
        assert!(!is_stdout_broken_pipe_panic(&*panic_text(&other_os_error)));
        assert!(!is_stdout_broken_pipe_panic(&*Box::new(
            "index out of bounds"
        )));
        let stderr = format!("failed printing to stderr: {}", broken_pipe_os_errors()[0]);
        assert!(!is_stdout_broken_pipe_panic(&*Box::new(stderr)));
        assert!(!is_stdout_broken_pipe_panic(&*Box::new(42_u8)));
    }

    #[test]
    fn an_error_without_a_broken_pipe_is_not_one() {
        let error = anyhow::Error::from(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(!is_stdout_broken_pipe_error(&error));
        let error = anyhow::anyhow!("plain failure");
        assert!(!is_stdout_broken_pipe_error(&error));
    }
}
