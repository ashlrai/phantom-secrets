//! `phantom audit hotspots` from a temp HOME: a read-only listing of the same
//! access-spike alerts the MCP tool reports, in human and JSON form.

mod common;

use assert_cmd::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET: &str = "HOTSPOT_FIXTURE_KEY";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

/// Unsigned audit lines are enough: hotspot detection reads only `ts` and `name`.
/// Seven quiet days set a baseline of 1/day; 30 accesses in the last hour is
/// a 5x spike over it.
fn write_spike_log(home: &std::path::Path) {
    let dir = home.join(".phantom");
    std::fs::create_dir_all(&dir).unwrap();
    let now = now_secs();
    let mut lines = Vec::new();
    for day in 1u64..=7 {
        lines.push(format!(
            r#"{{"seq":1,"ts":{},"op":"vault.retrieve","name":"{SECRET}","pid":1,"process":"phantom"}}"#,
            now - day * 86400
        ));
    }
    for i in 0u64..30 {
        lines.push(format!(
            r#"{{"seq":1,"ts":{},"op":"vault.retrieve","name":"{SECRET}","pid":1,"process":"phantom"}}"#,
            now - 3600 + i * 100
        ));
    }
    std::fs::write(dir.join("audit.log"), lines.join("\n") + "\n").unwrap();
}

/// Mark the fixture secret acknowledged in the hotspot acks file.
fn write_ack(home: &std::path::Path, status: &str) {
    let line = format!(
        r#"{{"secret_name":"{SECRET}","ack_ts":{},"status":"{status}","snooze_until_ts":0}}"#,
        now_secs()
    );
    std::fs::write(
        home.join(".phantom").join("hotspot-alerts.jsonl"),
        line + "\n",
    )
    .unwrap();
}

fn hotspots(home: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    // PHANTOM_AUDIT=1 is deliberate: with it set, the emitting detector would
    // append `vault.hotspot_alert` events, so this proves the listing does not.
    cmd.current_dir(home)
        .env("HOME", home)
        .env("PHANTOM_AUDIT", "1")
        .env("NO_COLOR", "1")
        .args(["audit", "hotspots"])
        .args(extra);
    cmd.output().expect("run phantom audit hotspots")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn parse(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn hotspots_on_a_fresh_home_says_none_and_creates_no_log() {
    let tmp = common::canonical_tempdir();
    let out = hotspots(tmp.path(), &[]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("No hotspot alerts"),
        "{}",
        stdout(&out)
    );
    assert!(!tmp.path().join(".phantom/audit.log").exists());
}

#[test]
fn hotspots_json_reports_the_spike_with_the_mcp_keys() {
    let tmp = common::canonical_tempdir();
    write_spike_log(tmp.path());

    let out = hotspots(tmp.path(), &["--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = parse(&out);
    assert_eq!(v["total_alerts"], 1, "{v}");
    assert!(
        v["generated_at"].as_str().is_some_and(|s| s.ends_with('Z')),
        "{v}"
    );

    let alert = &v["alerts"][0];
    assert_eq!(alert["secret_name"], SECRET);
    assert_eq!(alert["ack_status"], "unacked");
    assert_eq!(alert["alert_level"], "high");
    assert!(alert["current_velocity"].as_u64().unwrap() >= 30, "{v}");
    assert!(
        alert["trigger"]
            .as_str()
            .unwrap()
            .contains("velocity_spike"),
        "{v}"
    );
}

#[test]
fn hotspots_listing_never_grows_the_audit_log() {
    let tmp = common::canonical_tempdir();
    write_spike_log(tmp.path());
    let log = tmp.path().join(".phantom/audit.log");
    let before = std::fs::read(&log).unwrap();

    for extra in [&["--json"][..], &[][..]] {
        let out = hotspots(tmp.path(), extra);
        assert!(out.status.success(), "{}", stdout(&out));
    }

    assert_eq!(
        std::fs::read(&log).unwrap(),
        before,
        "repeated listings must not append vault.hotspot_alert events"
    );
}

#[test]
fn hotspots_human_output_names_the_secret_and_points_at_the_ack_path() {
    let tmp = common::canonical_tempdir();
    write_spike_log(tmp.path());

    let out = hotspots(tmp.path(), &[]);
    let text = stdout(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 hotspot alert · 1 unacked"), "{text}");
    assert!(text.contains(SECRET), "{text}");
    assert!(text.contains("velocity_spike"), "{text}");
    assert!(text.contains("phantom_audit_hotspot_alerts"), "{text}");
}

#[test]
fn hotspots_hides_acked_alerts_until_include_acked() {
    let tmp = common::canonical_tempdir();
    write_spike_log(tmp.path());
    write_ack(tmp.path(), "acked");

    let hidden = parse(&hotspots(tmp.path(), &["--json"]));
    assert_eq!(hidden["total_alerts"], 0, "{hidden}");

    let shown = parse(&hotspots(tmp.path(), &["--json", "--include-acked"]));
    assert_eq!(shown["total_alerts"], 1, "{shown}");
    assert_eq!(shown["alerts"][0]["ack_status"], "acked", "{shown}");

    let human = stdout(&hotspots(tmp.path(), &["--include-acked"]));
    assert!(human.contains("acked"), "{human}");
    assert!(human.contains("0 unacked"), "{human}");
}

#[test]
fn hotspots_name_filter_is_exact() {
    let tmp = common::canonical_tempdir();
    write_spike_log(tmp.path());

    let matched = parse(&hotspots(tmp.path(), &["--json", "--name", SECRET]));
    assert_eq!(matched["total_alerts"], 1, "{matched}");

    let other = parse(&hotspots(
        tmp.path(),
        &["--json", "--name", "HOTSPOT_FIXTURE"],
    ));
    assert_eq!(other["total_alerts"], 0, "{other}");
}
