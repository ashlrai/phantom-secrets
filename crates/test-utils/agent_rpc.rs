//! Bounded, leak-safe JSON-RPC client shared by executable integration tests.
use super::support::{finish_capture, Canary};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(30);

pub struct Rpc<'a> {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Vec<u8>>,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    canaries: &'a [&'a Canary],
    next_id: u64,
}

impl<'a> Rpc<'a> {
    pub fn start(mut command: std::process::Command, canaries: &'a [&'a Canary]) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch real MCP server");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("MCP stdout pipe");
        let mut stderr = child.stderr.take().expect("MCP stderr pipe");
        let (sender, lines) = mpsc::channel();
        let stdout = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut transcript = Vec::new();
            loop {
                let mut line = Vec::new();
                let read = reader
                    .read_until(b'\n', &mut line)
                    .expect("read MCP stdout");
                if read == 0 {
                    break;
                }
                transcript.extend_from_slice(&line);
                if sender.send(line).is_err() {
                    break;
                }
            }
            transcript
        });
        let stderr = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).expect("read MCP stderr");
            bytes
        });
        Self {
            child,
            stdin,
            lines,
            stdout: Some(stdout),
            stderr: Some(stderr),
            canaries,
            next_id: 0,
        }
    }

    pub fn send(&mut self, message: Value) {
        let input = self.stdin.as_mut().expect("live MCP input");
        assert!(serde_json::to_writer(&mut *input, &message).is_ok());
        assert!(input.write_all(b"\n").is_ok());
        assert!(input.flush().is_ok());
    }

    pub fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}));
        let started = Instant::now();
        loop {
            let remaining = DEADLINE
                .checked_sub(started.elapsed())
                .expect("MCP response deadline");
            let bytes = self
                .lines
                .recv_timeout(remaining)
                .expect("MCP response before deadline");
            for canary in self.canaries {
                canary.assert_absent(&bytes, "MCP raw protocol stdout");
            }
            let message: Value =
                serde_json::from_slice(&bytes).expect("MCP stdout must be JSON-RPC");
            assert_eq!(message["jsonrpc"], "2.0");
            if message["id"] == id {
                return message;
            }
        }
    }

    pub fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name":name, "arguments":arguments}))
    }

    pub fn finish(mut self) {
        drop(self.stdin.take());
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("MCP exit status") {
                assert!(status.success(), "MCP server must shut down cleanly");
                break;
            }
            assert!(started.elapsed() < DEADLINE, "MCP shutdown deadline");
            thread::sleep(Duration::from_millis(10));
        }
        let stdout = finish_capture(self.stdout.take().unwrap());
        let stderr = finish_capture(self.stderr.take().unwrap());
        assert!(!stdout.is_empty(), "protocol capture must be exercised");
        assert!(
            !stderr.is_empty(),
            "server startup tracing must be exercised"
        );
        for canary in self.canaries {
            canary.assert_absent(&stdout, "complete MCP stdout including shutdown");
            canary.assert_absent(&stderr, "complete MCP stderr and tracing");
        }
    }
}

impl Drop for Rpc<'_> {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
