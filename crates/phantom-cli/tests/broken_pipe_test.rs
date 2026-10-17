//! `phantom <cmd> | head` must not panic when the reader goes away early.
//!
//! Rust ignores SIGPIPE, so a write to a closed pipe returns EPIPE and
//! `println!` panics with exit 101. Phantom treats that as a quiet exit with
//! the shell's SIGPIPE status, 141, and leaves the SIGPIPE disposition alone so
//! `phantom exec` children keep their own.

mod common;

use phantom_core::config::PhantomConfig;
use std::io::Read;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

/// What `128 + SIGPIPE` reads as in a shell; Phantom exits with it on EPIPE.
const BROKEN_PIPE_EXIT: i32 = 141;

/// Commands that print to stdout and exit 0 in a project with no secrets,
/// without opening a vault.
const COMMANDS: &[&[&str]] = &[
    &["doctor"],
    &["status"],
    &["why", "NODE_ENV"],
    &["list"],
    &["list", "--json"],
    &["check", "--json"],
    &["audit", "path"],
];

/// A project with a default `.phantom.toml` and only non-secret config.
fn project() -> TempDir {
    let dir = common::canonical_tempdir();
    let config = PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(dir.path()));
    std::fs::write(
        dir.path().join(".phantom.toml"),
        toml::to_string_pretty(&config).expect("serialize config"),
    )
    .expect("write .phantom.toml");
    std::fs::write(dir.path().join(".env"), "NODE_ENV=development\nPORT=3000\n")
        .expect("write .env");
    dir
}

fn phantom(dir: &TempDir, args: &[&str]) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("phantom"));
    cmd.args(args)
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env_remove("PHANTOM_AUDIT")
        .stdin(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}

fn describe(args: &[&str], output: &Output) -> String {
    format!(
        "`phantom {}` exited {:?}, stderr: {}",
        args.join(" "),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_no_panic(args: &[&str], output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked") && !stderr.contains("Broken pipe"),
        "must not panic on a closed stdout: {}",
        describe(args, output)
    );
}

#[test]
fn every_command_prints_to_an_open_stdout() {
    // Guards the tests below: a command that printed nothing would pass them
    // without ever writing to a closed pipe.
    let dir = project();
    for args in COMMANDS {
        let output = phantom(&dir, args)
            .stdout(Stdio::piped())
            .output()
            .expect("run phantom");
        assert_eq!(output.status.code(), Some(0), "{}", describe(args, &output));
        assert!(!output.stdout.is_empty(), "{}", describe(args, &output));
    }
}

#[test]
fn stdout_closed_before_any_write_exits_141_without_panicking() {
    let dir = project();
    for args in COMMANDS {
        // The read end is closed before the child starts, so its first write
        // to stdout fails with EPIPE every time: no timing involved.
        let (reader, writer) = std::io::pipe().expect("create a pipe");
        drop(reader);
        let output = phantom(&dir, args)
            .stdout(writer)
            .output()
            .expect("run phantom");
        assert_no_panic(args, &output);
        assert_eq!(
            output.status.code(),
            Some(BROKEN_PIPE_EXIT),
            "{}",
            describe(args, &output)
        );
    }
}

#[test]
fn reader_that_closes_early_gets_a_quiet_exit() {
    let dir = project();
    for args in COMMANDS {
        // `| head -c 1`: read one byte, then hang up. Whether the child still
        // has output to write by then depends on timing, so 0 and 141 both pass.
        let mut child = phantom(&dir, args)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn phantom");
        let mut stdout = child.stdout.take().expect("child stdout");
        let mut first = [0u8; 1];
        stdout.read_exact(&mut first).expect("read the first byte");
        drop(stdout);
        let output = child.wait_with_output().expect("wait for phantom");
        assert_no_panic(args, &output);
        let code = output.status.code();
        assert!(
            code == Some(0) || code == Some(BROKEN_PIPE_EXIT),
            "{}",
            describe(args, &output)
        );
    }
}
