mod common;

// Exercise the same buffered I/O loop as the executable without including
// process startup and scheduler latency in the per-line processing budget.
#[path = "../src/commands/redact.rs"]
mod redact;

use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn command(home: &TempDir) -> Command {
    // Keep the included command entry point live in this integration target.
    let _: fn() -> anyhow::Result<()> = redact::run;
    let mut command = Command::new(env!("CARGO_BIN_EXE_phantom"));
    command
        .current_dir(home.path())
        .env_clear()
        .env("HOME", home.path());
    command
}

fn fake_token(prefix: &str) -> String {
    let tail = if matches!(prefix, "AKIA" | "ASIA") {
        "FAKE".repeat(4)
    } else {
        "FAKE0".repeat(10)
    };
    format!("{prefix}{tail}")
}

const PREFIXES: &[&str] = &[
    "xapp-",
    "xoxa-",
    "xoxs-",
    "xoxr-",
    "ghu_",
    "ghs_",
    "ghr_",
    "ASIA",
    "xoxb-",
    "xoxp-",
    "ghp_",
    "gho_",
    "github_pat_",
    "sk-",
    "AKIA",
    "sk_live_",
    "sk_test_",
    "glpat-",
    "sk_",
    "pk_",
    "rk_",
    "whsec_",
    "shpat_",
    "Bearer ",
];

#[test]
fn every_provider_shape_is_redacted_and_short_noncredentials_survive() {
    for prefix in PREFIXES {
        let input = format!("before=\"{}\"; after\n", fake_token(prefix));
        let mut output = Vec::new();
        redact::stream(Cursor::new(input), &mut output).unwrap();
        assert!(
            output == b"before=\"[REDACTED]\"; after\n",
            "provider {prefix}"
        );

        // A Bearer value may legitimately be short; only the empty scheme
        // is a negative fixture. Provider-issued shapes have length minima.
        let tail = if *prefix == "Bearer " { "" } else { "short" };
        let input = format!("example={prefix}{tail}\n");
        output.clear();
        redact::stream(Cursor::new(input.as_bytes()), &mut output).unwrap();
        assert!(output == input.as_bytes(), "short noncredential {prefix}");
    }
}

#[test]
fn executable_preserves_nonsecret_bytes_and_redacts_multiple_tokens() {
    let home = common::canonical_tempdir();
    let mut child = command(&home)
        .args(["redact", "--stream"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = b"\xff\xfe ordinary UTF-8: \xe2\x98\x83\r\n\n".to_vec();
    input.extend_from_slice(
        format!("{} + {}\r\n", fake_token("xapp-"), fake_token("ghs_")).as_bytes(),
    );
    input.extend_from_slice(format!("last={}", fake_token("ASIA")).as_bytes());
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(output.stdout == b"\xff\xfe ordinary UTF-8: \xe2\x98\x83\r\n\n[REDACTED] + [REDACTED]\r\nlast=[REDACTED]");
    assert!(!home.path().join(".phantom").exists());
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn executable_flushes_each_line_before_eof_and_holds_partial_tokens() {
    let home = common::canonical_tempdir();
    let mut child = KillOnDrop(
        command(&home)
            .args(["redact", "--stream"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdin = child.0.stdin.take().unwrap();
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            match stdout.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => send.send(line).unwrap(),
                Err(_) => break,
            }
        }
    });

    stdin.write_all(b"ready\n").unwrap();
    let line = receive
        .recv_timeout(Duration::from_secs(5))
        .expect("complete line must flush while stdin remains open");
    assert!(line == b"ready\n");
    let token = fake_token("xapp-");
    stdin.write_all(&token.as_bytes()[..3]).unwrap();
    assert!(receive.recv_timeout(Duration::from_millis(30)).is_err());
    stdin.write_all(&token.as_bytes()[3..]).unwrap();
    stdin.write_all(b"\n").unwrap();
    let line = receive
        .recv_timeout(Duration::from_secs(5))
        .expect("redacted line must flush without waiting for EOF");
    assert!(line == b"[REDACTED]\n");
    drop(stdin);
    assert!(child.0.wait().unwrap().success());
    reader.join().unwrap();
    let mut stderr = Vec::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    assert!(stderr.is_empty());
}

struct SplitRead<'a> {
    bytes: &'a [u8],
    first: usize,
}

impl Read for SplitRead<'_> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        let count = self.bytes.len().min(target.len()).min(self.first);
        target[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        self.first = usize::MAX;
        Ok(count)
    }
}

#[test]
fn token_at_every_possible_read_split_is_redacted() {
    for prefix in PREFIXES {
        let input = format!("token={}\n", fake_token(prefix));
        for split in 1..input.len() {
            let reader = BufReader::new(SplitRead {
                bytes: input.as_bytes(),
                first: split,
            });
            let mut output = Vec::new();
            redact::stream(reader, &mut output).unwrap();
            assert!(
                output == b"token=[REDACTED]\n",
                "split {split}, provider {prefix}"
            );
        }
    }
}

/// Identical buffered line pipeline to `redact::stream` without the credential
/// scan. Measured on the same machine and build, it gives the per-line cost a
/// machine-relative bound: an absolute wall-clock limit fails on slower or
/// coverage-instrumented CI runners even when processing is healthy.
fn unscrubbed_line_pipeline(mut input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        let count = input
            .by_ref()
            .take(1024 * 1024)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            return Ok(());
        }
        output.write_all(&line)?;
        output.flush()?;
    }
}

fn min_call_duration(iterations: usize, mut call: impl FnMut(&mut Vec<u8>)) -> Duration {
    let mut output = Vec::with_capacity(8192);
    // Warm code/data caches once. Every measured iteration includes the real
    // read, detector, writes and flush; only process startup is excluded. The
    // minimum filters scheduler noise instead of averaging it into the bound.
    call(&mut output);
    (0..iterations)
        .map(|_| {
            output.clear();
            let start = Instant::now();
            call(&mut output);
            start.elapsed()
        })
        .min()
        .expect("at least one measured iteration")
}

#[test]
fn line_processing_stays_proportional_to_the_buffered_pipeline() {
    let line = format!(
        "{} token={} provider={} message=finished\n",
        "ordinary log context ".repeat(30),
        fake_token("xapp-"),
        fake_token("github_pat_")
    );
    assert!(line.len() <= 1024);

    // Scanning every detector over the line legitimately costs orders of
    // magnitude more than the bare buffered copy; the bound sits well above
    // that healthy ratio but far below any superlinear or per-line fixed-cost
    // regression, on any machine. The absolute floor keeps a sub-millisecond
    // sanity bound where the bare pipeline is too fast to measure.
    const SCAN_WORK_BUDGET: u32 = 1024;
    let bare = min_call_duration(100, |out| {
        unscrubbed_line_pipeline(Cursor::new(line.as_bytes()), out).unwrap();
    });
    let scrubbed = min_call_duration(100, |out| {
        redact::stream(Cursor::new(line.as_bytes()), out).unwrap();
    });
    let ceiling = (bare * SCAN_WORK_BUDGET).max(Duration::from_millis(1));
    assert!(
        scrubbed <= ceiling,
        "line processing took {scrubbed:?}; bare pipeline took {bare:?}"
    );

    // An eight-times-longer single line must cost close to eight times more;
    // superlinear processing blows far past this bound on every machine.
    const LINEAR_BUDGET: u32 = 16;
    let long_line = format!(
        "{} token={} provider={} message=finished\n",
        "ordinary log context ".repeat(30 * 8),
        fake_token("xapp-"),
        fake_token("github_pat_")
    );
    let long = min_call_duration(100, |out| {
        redact::stream(Cursor::new(long_line.as_bytes()), out).unwrap();
    });
    assert!(
        long <= scrubbed * LINEAR_BUDGET,
        "8x line processing took {long:?}; 1x took {scrubbed:?}"
    );
}

struct ReadFailure<'a> {
    prefix: &'a [u8],
}

impl Read for ReadFailure<'_> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if self.prefix.is_empty() {
            return Err(io::Error::other("simulated input failure"));
        }
        let count = target.len().min(self.prefix.len());
        target[..count].copy_from_slice(&self.prefix[..count]);
        self.prefix = &self.prefix[count..];
        Ok(count)
    }
}

#[test]
fn read_error_never_emits_an_incomplete_line() {
    let input = fake_token("xapp-");
    let reader = BufReader::new(ReadFailure {
        prefix: input.as_bytes(),
    });
    let mut output = Vec::new();
    assert!(redact::stream(reader, &mut output).is_err());
    assert!(output.is_empty());
}

struct FlushFailure;

impl Write for FlushFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

#[test]
fn output_flush_errors_propagate() {
    let input = format!("{}\n", fake_token("xapp-"));
    let error = redact::stream(Cursor::new(input), FlushFailure).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn oversized_line_fails_closed_without_emitting_it() {
    let mut input = vec![b'a'; 1024 * 1024 + 1];
    input.extend_from_slice(fake_token("xapp-").as_bytes());
    input.push(b'\n');
    let mut output = Vec::new();
    assert!(redact::stream(Cursor::new(input), &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn exact_line_limit_is_accepted_and_next_oversized_line_is_withheld() {
    let token = fake_token("xapp-");
    let mut input = vec![b' '; 1024 * 1024 - token.len() - 1];
    input.extend_from_slice(token.as_bytes());
    input.push(b'\n');
    let mut output = Vec::new();
    redact::stream(Cursor::new(&input), &mut output).unwrap();
    let mut expected = vec![b' '; 1024 * 1024 - token.len() - 1];
    expected.extend_from_slice(b"[REDACTED]\n");
    assert!(output == expected);

    input.extend(std::iter::repeat_n(b'a', 1024 * 1024 + 1));
    output.clear();
    assert!(redact::stream(Cursor::new(input), &mut output).is_err());
    assert!(output == expected);
}

#[test]
fn empty_input_and_clean_eof_are_lossless() {
    for input in [b"".as_slice(), b"ordinary text", b"one\r\ntwo\n\n"] {
        let mut output = Vec::new();
        redact::stream(Cursor::new(input), &mut output).unwrap();
        assert!(output == input);
    }
}

#[test]
fn stream_flag_is_required_and_json_is_rejected() {
    let home = common::canonical_tempdir();
    for args in [vec!["redact"], vec!["redact", "--stream", "--json"]] {
        let output = command(&home).args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
