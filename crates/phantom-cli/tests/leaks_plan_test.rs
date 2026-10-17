//! `phantom leaks plan` is a read-only dry run: it must print the planned
//! response, leave every file under HOME untouched, and never print values.

mod common;

use assert_cmd::Command;
use std::collections::BTreeMap;
use std::path::Path;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().display().to_string();
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn seed(home: &Path, secret: &str, confidence: f64) {
    let dir = home.join(".phantom");
    std::fs::create_dir_all(&dir).unwrap();
    let now = now_unix();
    let line = format!(
        r#"{{"incident_id":"abc123","secret_name":"{secret}","location_label":"body","first_seen_ts":{},"last_seen_ts":{},"event_count":4,"confidence":{confidence},"remediation":"x"}}"#,
        now - 120,
        now - 60
    );
    std::fs::write(dir.join("leak-incidents.jsonl"), format!("{line}\n")).unwrap();
}

fn plan(home: &Path, extra: &[&str]) -> String {
    let out = Command::cargo_bin("phantom")
        .expect("binary not found")
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .args(["leaks", "plan"])
        .args(extra)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(out).unwrap()
}

#[test]
fn plan_json_is_dry_run_and_writes_nothing() {
    let tmp = common::canonical_tempdir();
    seed(tmp.path(), "STRIPE_SECRET_KEY", 0.95);
    let before = snapshot(tmp.path());

    let stdout = plan(tmp.path(), &["--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["plan"][0]["secret_name"], "STRIPE_SECRET_KEY");
    assert_eq!(v["plan"][0]["action"], "revoke_and_rotate");
    assert_eq!(v["plan"][0]["provider"], "stripe");

    assert_eq!(before, snapshot(tmp.path()), "plan must not write files");
}

#[test]
fn plan_text_low_confidence_is_review_and_writes_nothing() {
    let tmp = common::canonical_tempdir();
    seed(tmp.path(), "SOME_UNKNOWN_NAME", 0.5);
    let before = snapshot(tmp.path());

    let stdout = plan(tmp.path(), &[]);
    assert!(stdout.contains("Dry run: nothing was changed"));
    assert!(stdout.contains("SOME_UNKNOWN_NAME"));
    assert!(stdout.contains("review"));
    assert!(!stdout.contains("revoke_and_rotate"));

    assert_eq!(before, snapshot(tmp.path()));
}

#[test]
fn plan_with_no_incidents_says_nothing_to_plan() {
    let tmp = common::canonical_tempdir();
    let stdout = plan(tmp.path(), &[]);
    assert!(stdout.contains("Nothing to plan"));
    assert!(snapshot(tmp.path()).is_empty());
}

#[test]
fn min_confidence_filters_plan() {
    let tmp = common::canonical_tempdir();
    seed(tmp.path(), "STRIPE_SECRET_KEY", 0.5);
    let stdout = plan(tmp.path(), &["--json", "--min-confidence", "0.9"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["plan"].as_array().unwrap().is_empty());
}
