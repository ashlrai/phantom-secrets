use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

const SECRET: &str = "synthetic-secret-never-forward-q8";
struct Feed(Child, Receiver<String>);
impl Feed {
    fn start(home: &std::path::Path, path: &std::path::Path, cursor: Option<&str>) -> Self {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("phantom"));
        command
            .env("HOME", home)
            .args(["--json", "audit", "feed", "--follow"])
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cursor) = cursor {
            command.args(["--cursor", cursor]);
        }
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        Self(child, rx)
    }
    fn event(&self, seq: u64) -> Value {
        let line = self
            .1
            .recv_timeout(Duration::from_secs(10))
            .expect("live event");
        assert!(!line.contains(SECRET));
        let event: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(event["seq"], seq);
        assert_eq!(event["operation"], "vault.store");
        // Decode the opaque cursor too: source strings must not hide inside it.
        let decoded = hex::decode(event["cursor"].as_str().unwrap()).unwrap();
        assert!(!String::from_utf8(decoded).unwrap().contains(SECRET));
        event
    }
}
impl Drop for Feed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn record(seq: u64) -> String {
    format!(
        "{}\n",
        json!({"seq":seq,"ts":42,"op":"vault.store","value":SECRET,"name":SECRET})
    )
}

#[test]
fn resume_append_partial_truncate_and_rotate_are_value_free() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("audit.log");
    std::fs::write(&path, record(1)).unwrap();
    let feed = Feed::start(home.path(), &path, None);
    let first = feed.event(1);
    drop(feed);
    let feed = Feed::start(home.path(), &path, first["cursor"].as_str());
    assert!(feed.1.recv_timeout(Duration::from_millis(250)).is_err());
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    let second = record(2);
    file.write_all(second.trim_end().as_bytes()).unwrap();
    assert!(feed.1.recv_timeout(Duration::from_millis(250)).is_err());
    file.write_all(b"\n").unwrap();
    let second_event = feed.event(2);
    // Truncate and regrow to the same length between polls; digest detects it.
    std::fs::write(&path, format!("{}{}", record(1), record(3))).unwrap();
    feed.event(1);
    feed.event(3);
    // A genuinely shorter file also restarts.
    std::fs::write(&path, record(5)).unwrap();
    feed.event(5);
    std::fs::rename(&path, home.path().join("audit.old")).unwrap();
    std::fs::write(&path, record(4)).unwrap();
    feed.event(4);
    drop(feed);
    // A saved cursor from a replaced file restarts at the new file's beginning.
    let feed = Feed::start(home.path(), &path, second_event["cursor"].as_str());
    feed.event(4);
}

#[test]
fn invalid_cursor_fails_without_echoing_input() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("phantom"))
        .env("HOME", home.path())
        .args(["--json", "audit", "feed", "--follow"])
        .arg(home.path().join("audit.log"))
        .args(["--cursor", SECRET])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
}
