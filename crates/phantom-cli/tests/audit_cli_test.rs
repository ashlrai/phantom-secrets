//! `phantom audit` from a fresh HOME: deletion of the log beside its signed
//! head checkpoint, the `verify --json` result, and date-range validation.

mod common;

use assert_cmd::Command;
use std::sync::Mutex;

/// Tests that point this process's HOME at a temp dir must not race.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Write two signed audit events under `home/.phantom` (names only, no values).
fn write_signed_events(home: &std::path::Path) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev_home = std::env::var("HOME").ok();
    let prev_audit = std::env::var("PHANTOM_AUDIT").ok();
    unsafe {
        std::env::set_var("HOME", home);
        std::env::set_var("PHANTOM_AUDIT", "1");
    }
    phantom_core::audit::log_result("vault.store", Some("VERIFY_FIXTURE_KEY"))
        .expect("write first audit event");
    phantom_core::audit::log_result("vault.retrieve", Some("VERIFY_FIXTURE_KEY"))
        .expect("write second audit event");
    unsafe {
        match prev_home {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
        match prev_audit {
            Some(p) => std::env::set_var("PHANTOM_AUDIT", p),
            None => std::env::remove_var("PHANTOM_AUDIT"),
        }
    }
    assert!(home.join(".phantom/audit.log").is_file());
    assert!(home.join(".phantom/audit-head.json").is_file());
}

fn verify(home: &std::path::Path, json: bool) -> std::process::Output {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(home)
        .env("HOME", home)
        .env_remove("PHANTOM_AUDIT")
        .args(["audit", "verify"]);
    if json {
        cmd.arg("--json");
    }
    cmd.output().expect("run phantom audit verify")
}

fn parse(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// Deleting only audit.log used to print "No audit log found" and exit 0,
/// although the retained head checkpoint proves the signed era existed.
#[test]
fn verify_fails_when_the_log_is_deleted_but_its_head_checkpoint_remains() {
    let tmp = common::canonical_tempdir();
    write_signed_events(tmp.path());
    std::fs::remove_file(tmp.path().join(".phantom/audit.log")).unwrap();

    let out = verify(tmp.path(), false);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout={stdout} stderr={stderr}"
    );
    assert!(!stdout.contains("No audit log found"), "{stdout}");
    assert!(stdout.contains("FAILED"), "{stdout}");
    assert!(
        stderr.contains("signed head checkpoint remains"),
        "{stderr}"
    );

    let out = verify(tmp.path(), true);
    assert_eq!(out.status.code(), Some(1));
    let v = parse(&out);
    assert_eq!(v["log_present"], false);
    assert_eq!(v["clean"], false);
    assert_eq!(v["head"], "mismatch");
}

#[test]
fn verify_json_reports_an_intact_chain() {
    let tmp = common::canonical_tempdir();
    write_signed_events(tmp.path());

    let out = verify(tmp.path(), true);
    assert!(out.status.success(), "{:?}", out);
    let v = parse(&out);
    assert_eq!(v["log_present"], true);
    assert_eq!(v["clean"], true);
    assert_eq!(v["verified"], 2);
    assert_eq!(v["tampered"], 0);
    assert_eq!(v["head"], "ok");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("VERIFY_FIXTURE_KEY"),
        "verify --json carries counts only"
    );
}

#[test]
fn verify_json_on_a_fresh_home_is_json() {
    let tmp = common::canonical_tempdir();
    let out = verify(tmp.path(), true);
    assert!(out.status.success(), "{:?}", out);
    let v = parse(&out);
    assert_eq!(v["log_present"], false);
    assert_eq!(v["verified"], 0);
}

/// A malformed or inverted date used to be read as "no bound": `audit report`
/// printed a whole-history compliance report and exited 0.
#[test]
fn audit_report_and_export_range_reject_bad_dates() {
    let tmp = common::canonical_tempdir();
    write_signed_events(tmp.path());

    for args in [
        &["audit", "report", "--from", "notadate"][..],
        &["audit", "report", "--to", "2026-02-30"][..],
        &[
            "audit",
            "report",
            "--from",
            "2026-05-01",
            "--to",
            "2026-01-01",
        ][..],
        &["audit", "export-range", "--from", "2026-13-45"][..],
        &[
            "audit",
            "export-range",
            "--from",
            "2026-05-01",
            "--to",
            "2026-01-01",
        ][..],
    ] {
        let out = Command::cargo_bin("phantom")
            .expect("binary not found")
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .args(args)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?} printed a report");
        assert!(
            stderr.contains("Invalid")
                && (stderr.contains("YYYY-MM-DD") || stderr.contains("after")),
            "{args:?}: {stderr}"
        );
    }

    let out = Command::cargo_bin("phantom")
        .expect("binary not found")
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .args(["audit", "report", "--from", "2020-01-01"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["period_from"], "2020-01-01T00:00:00Z");
}

/// `--min-confidence 5` used to print "No active leak incidents" and exit 0.
#[test]
fn audit_incidents_rejects_out_of_range_min_confidence() {
    let tmp = common::canonical_tempdir();
    for bad in ["5", "1.5", "NaN", "high"] {
        let out = Command::cargo_bin("phantom")
            .expect("binary not found")
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .args(["audit", "incidents", "--min-confidence", bad])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{bad}: {stderr}");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("No active leak incidents"));
        assert!(stderr.contains("--min-confidence"), "{bad}: {stderr}");
    }
    let out = Command::cargo_bin("phantom")
        .expect("binary not found")
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .args(["audit", "incidents", "--min-confidence", "0.9"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
}

/// The proxy only appends `proxy.response_leak` events; incidents are
/// persisted by the gated `audit alerts --backfill`. `audit incidents` used
/// to answer "No active leak incidents" (or `[]` with --json) while fresh leak
/// events sat in the audit log.
#[test]
fn audit_incidents_reports_leak_events_not_yet_persisted() {
    let tmp = common::canonical_tempdir();
    let phantom_dir = tmp.path().join(".phantom");
    std::fs::create_dir_all(&phantom_dir).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let line = |ts: u64| {
        format!(
            "{{\"ts\":{ts},\"op\":\"proxy.response_leak\",\"name\":\"OPENAI_API_KEY\",\"pid\":1,\"process\":\"phantom\"}}\n"
        )
    };
    std::fs::write(
        phantom_dir.join("audit.log"),
        format!("{}{}", line(now - 20), line(now - 10)),
    )
    .unwrap();

    let run = |args: &[&str]| {
        Command::cargo_bin("phantom")
            .expect("binary not found")
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .env_remove("PHANTOM_AUDIT")
            .args(args)
            .output()
            .unwrap()
    };

    let out = run(&["audit", "incidents", "--json"]);
    assert!(out.status.success(), "{out:?}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["incidents"], serde_json::json!([]));
    assert_eq!(
        report["uncorrelated_incidents"][0]["secret_name"],
        "OPENAI_API_KEY"
    );
    assert_eq!(report["uncorrelated_incidents"][0]["event_count"], 2);

    let out = run(&["audit", "incidents"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("not persisted yet"), "{stdout}");
    assert!(stdout.contains("unpersisted"), "{stdout}");
    assert!(stdout.contains("OPENAI_API_KEY"), "{stdout}");
    assert!(
        stdout.contains("phantom audit alerts --backfill"),
        "{stdout}"
    );

    // Read-only: nothing was persisted.
    assert!(!phantom_dir.join("leak-incidents.jsonl").exists());
}

/// With nothing found, --json keeps the same object shape (it used to print
/// a bare `[]`).
#[test]
fn audit_incidents_json_shape_is_stable_when_empty() {
    let tmp = common::canonical_tempdir();
    let out = Command::cargo_bin("phantom")
        .expect("binary not found")
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .args(["audit", "incidents", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["incidents"], serde_json::json!([]));
    assert_eq!(report["uncorrelated_incidents"], serde_json::json!([]));
}
