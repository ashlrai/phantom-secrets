//! Shared black-box helpers. Canaries are runtime-only and intentionally have
//! no Debug implementation: a failed assertion must never disclose a value.
use base64::Engine;
use rand::RngCore;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub struct Canary(String);

impl Canary {
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(format!("synthetic-only-{}", hex::encode(bytes)))
    }

    pub fn value(&self) -> &str {
        &self.0
    }

    pub fn assert_absent(&self, bytes: &[u8], surface: &str) {
        // Include common encodings so a structured result cannot hide a leak
        // by serializing the credential as hex or base64 instead of plaintext.
        for needle in [
            self.0.clone(),
            hex::encode(self.0.as_bytes()),
            base64::engine::general_purpose::STANDARD.encode(self.0.as_bytes()),
        ] {
            assert!(
                !bytes
                    .windows(needle.len())
                    .any(|part| part == needle.as_bytes()),
                "runtime canary leaked on {surface} (content withheld)"
            );
        }
    }
}

pub fn canonical_tempdir() -> tempfile::TempDir {
    let root = std::env::temp_dir()
        .canonicalize()
        .expect("canonical temp root");
    tempfile::Builder::new()
        .prefix("phantom-agent-novalue-")
        .tempdir_in(root)
        .expect("isolated fixture directory")
}

pub fn isolated_command(binary: impl AsRef<OsStr>, project: &Path, home: &Path) -> Command {
    let mut command = Command::new(binary);
    command.env_clear().current_dir(project);
    // Only executable discovery/platform essentials survive. In particular,
    // no developer credentials, agent context, or Phantom authority is copied.
    for name in ["PATH", "SystemRoot", "WINDIR", "PATHEXT"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("TMPDIR", home)
        .env("TMP", home)
        .env("TEMP", home)
        .env("NO_COLOR", "1")
        .env("PHANTOM_AUDIT", "1");
    command
}

pub fn assert_tree_value_free(root: &Path, canaries: &[&Canary]) -> usize {
    let mut count = 0;
    for entry in fs::read_dir(root).expect("read fixture directory") {
        let entry = entry.expect("read fixture entry");
        let kind = entry.file_type().expect("fixture entry type");
        assert!(!kind.is_symlink(), "unexpected fixture symlink");
        if kind.is_dir() {
            count += assert_tree_value_free(&entry.path(), canaries);
        } else {
            assert!(kind.is_file(), "unexpected special fixture file");
            let bytes = fs::read(entry.path()).expect("read fixture artifact");
            for canary in canaries {
                canary.assert_absent(&bytes, "persisted artifact or log");
            }
            count += 1;
        }
    }
    count
}

/// A descendant can retain an inherited pipe after the direct child exits.
/// Do not let that turn a failed shutdown contract into a hung test runner.
pub fn finish_capture(reader: std::thread::JoinHandle<Vec<u8>>) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !reader.is_finished() {
        assert!(
            Instant::now() < deadline,
            "output pipe did not close before deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    reader.join().expect("output reader")
}

/// Drain both pipes concurrently, with a deadline, so a noisy or stuck child
/// fails the test rather than deadlocking the workspace suite.
pub fn run(command: &mut Command) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch fixture process");
    let mut stdout = child.stdout.take().expect("stdout pipe");
    let mut stderr = child.stderr.take().expect("stderr pipe");
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).expect("capture stdout");
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).expect("capture stderr");
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll fixture process") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("fixture process exceeded deadline (output withheld)");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Output {
        status,
        stdout: finish_capture(out),
        stderr: finish_capture(err),
    }
}
