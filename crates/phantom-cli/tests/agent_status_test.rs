//! `phantom agent status` is read-only and value-free: it must write nothing
//! under HOME (not even on a fresh HOME) and never print nonces or hashes.

use assert_cmd::Command;
use std::collections::BTreeMap;
use std::path::Path;

fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            if p.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                walk(&p, root, out);
            } else {
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn status(home: &Path, args: &[&str]) -> String {
    let out = Command::cargo_bin("phantom")
        .expect("binary not found")
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .args(["agent", "status"])
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out).unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

const NONCE: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
const HASH: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

#[test]
fn fresh_home_writes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let before = snapshot(home.path());
    let v: serde_json::Value = serde_json::from_str(&status(home.path(), &["--json"])).unwrap();
    assert_eq!(v["approvals"]["pending"], 0);
    assert_eq!(v["approvals"]["key_present"], false);
    assert_eq!(v["leases"]["available"], false);
    let _ = status(home.path(), &[]);
    assert_eq!(before, snapshot(home.path()));
}

#[test]
fn counts_states_prints_no_nonce_or_hash_and_writes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".phantom");
    std::fs::create_dir_all(&dir).unwrap();
    let t = now();
    let rec = |approved: bool, exp: u64, tool: &str| {
        format!(
            r#"{{"nonce":"{NONCE}","tool_name":"{tool}","arg_hash":"{HASH}","project_id":"/p","effect_summary":"SECRET_EFFECT","parameter_summary":"SECRET_PARAMS","created_at":{},"expires_at":{exp},"approved":{approved}}}"#,
            t - 10
        )
    };
    let body = format!(
        "{}\n{}\n{}\n",
        rec(false, t + 300, "phantom_a"),
        rec(true, t + 300, "phantom_b"),
        rec(false, t - 1, "phantom_c")
    );
    std::fs::write(dir.join("mcp-approvals.jsonl"), body).unwrap();
    std::fs::write(dir.join("mcp-approval-key"), "00ff00ff").unwrap();
    let before = snapshot(home.path());

    let text = status(home.path(), &["--json"]);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["approvals"]["pending"], 1);
    assert_eq!(v["approvals"]["approved_unused"], 1);
    assert_eq!(v["approvals"]["expired"], 1);
    assert_eq!(v["approvals"]["key_present"], true);
    let human = status(home.path(), &[]);
    for out in [&text, &human] {
        for banned in [NONCE, HASH, "SECRET_EFFECT", "SECRET_PARAMS", "00ff00ff"] {
            assert!(!out.contains(banned), "leaked {banned}");
        }
    }
    assert!(human.contains("phantom_a"));
    assert_eq!(before, snapshot(home.path()));
}
