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
        r#"{{"incident_id":"abc123","secret_name":"{secret}","location_label":"body","first_seen_ts":{},"last_seen_ts":{},"event_count":4,"confidence":{confidence},"remediation":"rk_live_value_that_must_not_be_printed"}}"#,
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
    assert_eq!(
        v["plan"][0]["manual_rotation_location"],
        "https://dashboard.stripe.com/apikeys"
    );
    assert_eq!(v["plan"][0]["live_rotation"], "disabled_in_this_build");
    assert_eq!(v["live_revoke_available"], false);

    assert!(!stdout.contains("rk_live_value_that_must_not_be_printed"));

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

fn plan_in(home: &Path, cwd: &Path, extra: &[&str]) -> assert_cmd::assert::Assert {
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .current_dir(cwd)
        .args(["leaks", "plan"])
        .args(extra)
        .assert()
}

fn write_policy(cwd: &Path, body: &str) {
    std::fs::write(
        cwd.join(".phantom.toml"),
        format!("[phantom]\nversion = \"1\"\nproject_id = \"abc123\"\n{body}"),
    )
    .unwrap();
}

#[test]
fn on_leak_off_prints_nothing_to_plan() {
    let tmp = common::canonical_tempdir();
    let proj = common::canonical_tempdir();
    seed(tmp.path(), "STRIPE_SECRET_KEY", 0.95);
    write_policy(proj.path(), "[leak_response]\non_leak = \"off\"\n");
    let out = plan_in(tmp.path(), proj.path(), &["--json"]).success();
    let v: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(v["on_leak"], "off");
    assert_eq!(v["plan"].as_array().unwrap().len(), 0);
    // A repository's policy must not hide the user's active incidents.
    assert_eq!(v["suppressed_incidents"], 1);
}

#[test]
fn on_leak_off_text_still_reports_active_incidents() {
    let tmp = common::canonical_tempdir();
    let proj = common::canonical_tempdir();
    seed(tmp.path(), "STRIPE_SECRET_KEY", 0.95);
    write_policy(proj.path(), "[leak_response]\non_leak = \"off\"\n");
    let out = plan_in(tmp.path(), proj.path(), &[]).success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        stdout.contains("1 active leak incident(s) exist and are not planned"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains("Nothing to plan"), "stdout: {stdout}");
}

#[test]
fn on_leak_off_with_no_incidents_says_nothing_to_plan() {
    let tmp = common::canonical_tempdir();
    let proj = common::canonical_tempdir();
    write_policy(proj.path(), "[leak_response]\non_leak = \"off\"\n");
    let out = plan_in(tmp.path(), proj.path(), &["--json"]).success();
    let v: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(v["suppressed_incidents"], 0);
}

#[test]
fn on_leak_default_is_plan() {
    let tmp = common::canonical_tempdir();
    let proj = common::canonical_tempdir();
    seed(tmp.path(), "STRIPE_SECRET_KEY", 0.95);
    write_policy(proj.path(), "");
    let out = plan_in(tmp.path(), proj.path(), &["--json"]).success();
    let v: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(v["on_leak"], "plan");
    assert_eq!(v["live_revoke_available"], false);
    assert_eq!(v["plan"][0]["action"], "revoke_and_rotate");
}

#[test]
fn on_leak_revoke_without_opt_in_fails_closed() {
    let tmp = common::canonical_tempdir();
    let proj = common::canonical_tempdir();
    seed(tmp.path(), "STRIPE_SECRET_KEY", 0.95);
    write_policy(proj.path(), "[leak_response]\non_leak = \"revoke\"\n");
    let out = plan_in(tmp.path(), proj.path(), &[]).failure();
    let err = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(err.contains("allow_revoke"), "stderr: {err}");
}

#[test]
fn on_leak_revoke_opted_in_still_only_plans() {
    let tmp = common::canonical_tempdir();
    let proj = common::canonical_tempdir();
    seed(tmp.path(), "STRIPE_SECRET_KEY", 0.95);
    write_policy(
        proj.path(),
        "[leak_response]\non_leak = \"revoke\"\nallow_revoke = true\n",
    );
    let before = snapshot(tmp.path());
    let out = plan_in(tmp.path(), proj.path(), &[]).success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(stdout.contains("live revoke is disabled in this build"));
    assert!(stdout.contains("Dry run: nothing was changed"));
    assert_eq!(before, snapshot(tmp.path()));
}
