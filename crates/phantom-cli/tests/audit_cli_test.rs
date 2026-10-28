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
    // Both events must share one hour bucket (ts / 3600) to form one
    // incident. `now - 20` and `now - 10` split across buckets when the test
    // runs in the first 20 seconds of an hour, so anchor them to the start of
    // the previous hour instead.
    let hour_start = (now / 3600 - 1) * 3600;
    std::fs::write(
        phantom_dir.join("audit.log"),
        format!("{}{}", line(hour_start + 100), line(hour_start + 110)),
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

/// `--window` used to round up to 7 or 30 days (`--window 3` covered a week,
/// `--window 90` only 30 days) while the JSON echoed the requested value.
#[test]
fn audit_analytics_window_is_the_exact_lookback() {
    let tmp = common::canonical_tempdir();
    let phantom_dir = tmp.path().join(".phantom");
    std::fs::create_dir_all(&phantom_dir).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let day = 86_400_u64;
    let line = |ts: u64, entry_name: &str| {
        format!(
            "{{\"ts\":{ts},\"op\":\"vault.retrieve\",\"name\":\"{entry_name}\",\"pid\":1,\"process\":\"phantom\"}}\n"
        )
    };
    std::fs::write(
        phantom_dir.join("audit.log"),
        [
            line(now - 60 * day, "WINDOW_60D"),
            line(now - 5 * day, "WINDOW_5D"),
            line(now - 3600, "WINDOW_1H"),
        ]
        .concat(),
    )
    .unwrap();

    let names_for = |window: &str| -> Vec<String> {
        let out = Command::cargo_bin("phantom")
            .expect("binary not found")
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .env_remove("PHANTOM_AUDIT")
            .args(["audit", "analytics", "--window", window])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["window_days"], window.parse::<u32>().unwrap());
        let mut names: Vec<String> = report["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        names
    };

    assert_eq!(names_for("3"), ["WINDOW_1H"]);
    assert_eq!(names_for("90"), ["WINDOW_1H", "WINDOW_5D", "WINDOW_60D"]);
    assert_eq!(names_for("0"), ["WINDOW_1H", "WINDOW_5D", "WINDOW_60D"]);
}

/// Anomaly-score flags use the MCP tools' rule: clamped to 0.0..=1.0 and NaN
/// refused. `--min-anomaly-score NaN` used to be accepted and match nothing.
#[test]
fn audit_score_flags_clamp_and_refuse_nan() {
    let tmp = common::canonical_tempdir();
    let phantom_dir = tmp.path().join(".phantom");
    std::fs::create_dir_all(&phantom_dir).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(
        phantom_dir.join("audit.log"),
        format!(
            "{{\"ts\":{},\"op\":\"vault.retrieve\",\"name\":\"SCORED_ENTRY\",\"pid\":1,\"process\":\"phantom\"}}\n",
            now - 100
        ),
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

    for args in [
        &["audit", "stats", "--json", "--min-anomaly-score", "NaN"][..],
        &["audit", "export", "--min-anomaly-score", "NaN"][..],
        &["audit", "analytics", "--min-anomaly-score", "NaN"][..],
        &["audit", "anomalies", "--threshold", "NaN"][..],
    ] {
        let out = run(args);
        assert!(!out.status.success(), "{args:?}: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("NaN"), "{args:?}: {stderr}");
    }

    // Below the range is the same as 0.0: every secret is kept.
    let out = run(&["audit", "analytics", "--min-anomaly-score=-1"]);
    assert!(out.status.success(), "{out:?}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["records"][0]["name"], "SCORED_ENTRY");
}

fn show(home: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(home)
        .env("HOME", home)
        .env_remove("PHANTOM_AUDIT")
        .args(["audit", "show", "--json"])
        .args(extra);
    cmd.output().expect("run phantom audit show")
}

/// `audit show --output` writes exactly what stdout would have held to a new
/// file, prints one summary line, and never overwrites an existing file.
#[test]
fn show_output_writes_the_full_report_to_a_new_file_and_prints_a_summary() {
    let tmp = common::canonical_tempdir();
    write_signed_events(tmp.path());
    let plain = show(tmp.path(), &[]);
    assert!(plain.status.success());

    let dest = tmp.path().join("audit-report.jsonl");
    let out = show(tmp.path(), &["--output", dest.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert_eq!(std::fs::read(&dest).unwrap(), plain.stdout);
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    let n = String::from_utf8_lossy(&plain.stdout).lines().count();
    assert!(n >= 2, "fixture events missing");
    assert!(stdout.contains(&format!("wrote {n} line(s)")), "{stdout}");
    assert!(!stdout.contains("VERIFY_FIXTURE_KEY"), "{stdout}");

    let again = show(tmp.path(), &["--output", dest.to_str().unwrap()]);
    assert!(!again.status.success());
    assert_eq!(std::fs::read(&dest).unwrap(), plain.stdout);
}

#[test]
fn default_json_query_and_since_are_machine_readable() {
    let tmp = common::canonical_tempdir();
    write_signed_events(tmp.path());
    let out = Command::cargo_bin("phantom")
        .unwrap()
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .args(["audit", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|v| v["actor"] == "phantom" && v["outcome"] == "success"));
    let ts = rows[0]["ts"].as_u64().unwrap().to_string();
    let inclusive = Command::cargo_bin("phantom")
        .unwrap()
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .args(["audit", "--json", "--since", &ts])
        .output()
        .unwrap();
    assert!(inclusive.status.success());
    assert!(inclusive.stdout == text.as_bytes());
    let future = Command::cargo_bin("phantom")
        .unwrap()
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .args(["audit", "--json", "--since", "18446744073709551615"])
        .output()
        .unwrap();
    assert!(future.status.success());
    assert!(future.stdout.is_empty());
    Command::cargo_bin("phantom")
        .unwrap()
        .env("HOME", tmp.path())
        .args(["audit", "--json", "--since", "invalid"])
        .assert()
        .failure();
}

#[test]
fn unknown_engine_exec_is_refused_before_project_or_child_access() {
    let tmp = common::canonical_tempdir();
    let out = Command::cargo_bin("phantom")
        .unwrap()
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("PHANTOM_ENGINE_ID", "synthetic-unknown-engine")
        .args(["exec", "--", "must-never-run"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("synthetic-unknown-engine"));
    let text = std::fs::read_to_string(tmp.path().join(".phantom/audit.log")).unwrap();
    assert!(!text.contains("synthetic-unknown-engine"));
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        rows.iter()
            .filter(|v| v["op"] == "engine.refused" && v["outcome"] == "refused")
            .count(),
        1
    );
}

#[test]
fn unknown_engine_mcp_is_refused_before_server_initialization() {
    let tmp = common::canonical_tempdir();
    let out = Command::cargo_bin("phantom")
        .unwrap()
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("PHANTOM_ENGINE_ID", "synthetic-unknown-engine")
        .args(["mcp", "serve"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("synthetic-unknown-engine"));
    let text = std::fs::read_to_string(tmp.path().join(".phantom/audit.log")).unwrap();
    assert!(!text.contains("synthetic-unknown-engine"));
    assert!(text
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|event| event["op"] == "engine.refused" && event["outcome"] == "refused"));
}
