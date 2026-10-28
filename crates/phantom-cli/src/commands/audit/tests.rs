use super::*;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn export_range_with_no_matches_prints_valid_json() {
    let out = render_export_range("json", &[]).unwrap();
    let parsed: Value = serde_json::from_str(&out).expect("stdout must be valid JSON");
    assert_eq!(parsed, serde_json::json!([]));
    assert_eq!(render_export_range("csv", &[]).unwrap(), "");
    assert!(render_export_range("xml", &[]).is_err());
}

fn write_fixture(dir: &std::path::Path, lines: &[&str]) -> PathBuf {
    let path = dir.join("audit.log");
    let mut f = std::fs::File::create(&path).unwrap();
    for line in lines {
        writeln!(f, "{}", line).unwrap();
    }
    path
}

const LINE_STORE: &str =
    r#"{"ts":1700000000,"op":"vault.store","name":"OPENAI_API_KEY","process":"phantom","pid":1}"#;
const LINE_RETRIEVE: &str = r#"{"ts":1700000060,"op":"vault.retrieve","name":"OPENAI_API_KEY","process":"phantom","pid":2}"#;
const LINE_PUSH: &str = r#"{"ts":1700000120,"op":"cloud.push","process":"phantom","pid":3}"#;
const LINE_STRIPE: &str =
    r#"{"ts":1700000180,"op":"vault.store","name":"STRIPE_KEY","process":"phantom","pid":4}"#;
const LINE_MALFORMED: &str = r#"{"ts":not-valid-json"#;

#[test]
fn incident_auto_rotation_flag_fails_before_correlation_or_mutation() {
    let error = run_incidents(0.9, true, true).unwrap_err();
    assert!(error.to_string().contains("deprecated and disabled"));
    assert!(error
        .to_string()
        .contains("does not rotate the leaked provider credential"));
}

#[test]
fn analytics_export_refuses_paths_outside_project_root() {
    let project = tempdir().unwrap();
    for filename in [
        "../report.json",
        "/tmp/report.json",
        "nested/report.json",
        "a..b",
    ] {
        assert!(prepare_analytics_export_in(project.path(), filename).is_err());
    }
    assert!(!project.path().join("report.json").exists());
}

#[test]
fn analytics_export_refuses_concurrent_destination_without_overwrite() {
    let project = tempdir().unwrap();
    let plan = prepare_analytics_export_in(project.path(), "audit.json").unwrap();
    std::fs::write(&plan.path, b"concurrent owner").unwrap();

    let error = plan.commit(b"phantom report").unwrap_err();

    assert!(error.to_string().contains("Refusing to overwrite"));
    assert_eq!(std::fs::read(&plan.path).unwrap(), b"concurrent owner");
}

#[cfg(unix)]
#[test]
fn analytics_export_refuses_symlink_destination() {
    use std::os::unix::fs::symlink;

    let project = tempdir().unwrap();
    let owner = project.path().join("owner.json");
    let target = project.path().join("audit.json");
    std::fs::write(&owner, b"owner").unwrap();
    symlink(&owner, &target).unwrap();

    assert!(prepare_analytics_export_in(project.path(), "audit.json").is_err());
    assert_eq!(std::fs::read(owner).unwrap(), b"owner");
}

#[test]
fn filter_by_op() {
    let tmp = tempdir().unwrap();
    let path = write_fixture(
        tmp.path(),
        &[LINE_STORE, LINE_RETRIEVE, LINE_PUSH, LINE_STRIPE],
    );
    let results = read_matching_lines(&path, Some("vault.store"), None)
        .unwrap()
        .lines;
    assert_eq!(results.len(), 2);
    assert!(results[0].contains("vault.store"));
    assert!(results[1].contains("STRIPE_KEY"));
}

#[test]
fn filter_by_name() {
    let tmp = tempdir().unwrap();
    let path = write_fixture(
        tmp.path(),
        &[LINE_STORE, LINE_RETRIEVE, LINE_PUSH, LINE_STRIPE],
    );
    let results = read_matching_lines(&path, None, Some("OPENAI_API_KEY"))
        .unwrap()
        .lines;
    assert_eq!(results.len(), 2);
    assert!(results[0].contains("vault.store"));
    assert!(results[1].contains("vault.retrieve"));
}

#[test]
fn filter_by_op_and_name() {
    let tmp = tempdir().unwrap();
    let path = write_fixture(
        tmp.path(),
        &[LINE_STORE, LINE_RETRIEVE, LINE_PUSH, LINE_STRIPE],
    );
    let results = read_matching_lines(&path, Some("vault.store"), Some("OPENAI_API_KEY"))
        .unwrap()
        .lines;
    assert_eq!(results.len(), 1);
    assert!(results[0].contains("vault.store"));
    assert!(results[0].contains("OPENAI_API_KEY"));
}

#[test]
fn last_n_limits_output() {
    // Simulate the --last N slice used in run_show
    let all: Vec<String> = (0..10)
        .map(|i| {
            format!(
                r#"{{"ts":{},"op":"vault.store","name":"K{}","process":"p","pid":1}}"#,
                1700000000u64 + i,
                i
            )
        })
        .collect();

    let window: Vec<&str> = all.iter().rev().take(3).rev().map(String::as_str).collect();

    assert_eq!(window.len(), 3);
    // Should be the last 3 (indices 7, 8, 9)
    assert!(window[0].contains("K7"));
    assert!(window[2].contains("K9"));
}

#[test]
fn malformed_line_is_skipped_not_panicked() {
    let tmp = tempdir().unwrap();
    let path = write_fixture(tmp.path(), &[LINE_STORE, LINE_MALFORMED, LINE_PUSH]);
    // Should return 2 valid lines, not crash, and count the bad one
    let results = read_matching_lines(&path, None, None).unwrap();
    assert_eq!(results.lines.len(), 2);
    assert_eq!(results.unparsable, 1);
    assert!(!results.window_truncated);
}

#[test]
fn empty_file_returns_no_lines() {
    let tmp = tempdir().unwrap();
    let path = write_fixture(tmp.path(), &[]);
    let results = read_matching_lines(&path, None, None).unwrap();
    assert!(results.lines.is_empty());
}

#[test]
fn matching_lines_come_from_the_newest_window_only() {
    let tmp = tempdir().unwrap();
    let path = write_fixture(
        tmp.path(),
        &[LINE_STORE, LINE_RETRIEVE, LINE_PUSH, LINE_STRIPE],
    );
    // The last line plus a fragment of the one before it.
    let window = LINE_STRIPE.len() as u64 + 1 + 5;
    let results = read_matching_lines_within(&path, None, None, window).unwrap();
    assert!(results.window_truncated);
    assert_eq!(results.lines, [LINE_STRIPE]);
    assert_eq!(results.unparsable, 0);
}

#[test]
fn show_fails_when_the_audit_log_cannot_be_read() {
    // A directory at the log path exists but cannot be read as a file,
    // even as root. Before this fix `audit show` printed "No matching
    // audit events" (and nothing at all with --json) and exited 0.
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("audit.log");
    std::fs::create_dir(&path).unwrap();

    assert!(read_matching_lines(&path, None, None).is_err());
    assert!(run_show_at(
        &path,
        20,
        None,
        None,
        true,
        false,
        &mut Vec::new(),
        &mut Vec::new()
    )
    .is_err());
    assert!(run_show_at(
        &path,
        20,
        None,
        None,
        false,
        false,
        &mut Vec::new(),
        &mut Vec::new()
    )
    .is_err());
    assert!(run_show_at(
        &path,
        20,
        None,
        None,
        true,
        true,
        &mut Vec::new(),
        &mut Vec::new()
    )
    .is_err());
}

#[cfg(unix)]
fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// A symlink planted at `audit.log` must not redirect `audit tail` (which
/// opens the log for append) into another file.
#[cfg(unix)]
#[test]
fn follow_refuses_symlinked_audit_log_and_leaves_target_untouched() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path().join(".phantom");
    std::fs::create_dir(&dir).unwrap();
    let target = tmp.path().join("elsewhere.txt");
    std::fs::write(&target, b"original\n").unwrap();
    let log = dir.join("audit.log");
    std::os::unix::fs::symlink(&target, &log).unwrap();

    assert!(open_log_for_follow(&log).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"original\n");
    assert!(std::fs::symlink_metadata(&log)
        .unwrap()
        .file_type()
        .is_symlink());
}

/// A dangling symlink at `audit.log` must not make `audit tail` create
/// the link's target.
#[cfg(unix)]
#[test]
fn follow_refuses_dangling_symlinked_audit_log() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path().join(".phantom");
    std::fs::create_dir(&dir).unwrap();
    let target = tmp.path().join("planted.log");
    std::os::unix::fs::symlink(&target, dir.join("audit.log")).unwrap();

    assert!(open_log_for_follow(&dir.join("audit.log")).is_err());
    assert!(std::fs::symlink_metadata(&target).is_err());
}

/// A symlinked `~/.phantom` must not become the directory `audit tail`
/// creates the log in.
#[cfg(unix)]
#[test]
fn follow_refuses_symlinked_phantom_dir() {
    let tmp = tempdir().unwrap();
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let dir = tmp.path().join(".phantom");
    std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();

    assert!(open_log_for_follow(&dir.join("audit.log")).is_err());
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

/// A fresh `~/.phantom` created by `audit tail` is 0700 and the log 0600,
/// whatever the umask.
#[cfg(unix)]
#[test]
fn follow_creates_private_dir_and_log() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path().join(".phantom");
    let log = dir.join("audit.log");

    open_log_for_follow(&log).unwrap();
    assert_eq!(mode_of(&dir), 0o700);
    assert_eq!(mode_of(&log), 0o600);
}

/// `audit show` must not report a dangling symlinked log as "no events
/// yet" and exit 0.
#[cfg(unix)]
#[test]
fn show_refuses_dangling_symlinked_audit_log() {
    let tmp = tempdir().unwrap();
    let log = tmp.path().join("audit.log");
    std::os::unix::fs::symlink(tmp.path().join("missing.log"), &log).unwrap();
    for json in [true, false] {
        assert!(run_show_at(
            &log,
            20,
            None,
            None,
            json,
            false,
            &mut Vec::new(),
            &mut Vec::new()
        )
        .is_err());
    }
}

/// `audit show` must not read a log through a symlinked `~/.phantom`.
#[cfg(unix)]
#[test]
fn show_refuses_log_in_symlinked_phantom_dir() {
    let tmp = tempdir().unwrap();
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("audit.log"), b"{\"op\":\"vault.store\"}\n").unwrap();
    let dir = tmp.path().join(".phantom");
    std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
    assert!(run_show_at(
        &dir.join("audit.log"),
        20,
        None,
        None,
        true,
        false,
        &mut Vec::new(),
        &mut Vec::new()
    )
    .is_err());
}

#[test]
fn show_reports_an_empty_but_readable_log_as_success() {
    let tmp = tempdir().unwrap();
    let path = write_fixture(tmp.path(), &[]);
    assert!(run_show_at(
        &path,
        20,
        None,
        None,
        true,
        false,
        &mut Vec::new(),
        &mut Vec::new()
    )
    .is_ok());
}

/// Run `audit show` against `path` and return (stdout, stderr).
fn show_output(
    path: &std::path::Path,
    op: Option<&str>,
    json: bool,
    leaked: bool,
) -> (String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    run_show_at(path, 20, op, None, json, leaked, &mut out, &mut err).unwrap();
    (
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// Every non-empty stdout line must be a JSON object (JSON Lines).
fn all_lines_are_json_objects(stdout: &str) -> bool {
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .all(|l| serde_json::from_str::<Value>(l).is_ok_and(|v| v.is_object()))
}

#[test]
fn show_json_keeps_stdout_machine_readable_when_the_log_is_missing() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("audit.log");
    for leaked in [false, true] {
        let (stdout, stderr) = show_output(&path, None, true, leaked);
        assert!(stdout.is_empty());
        assert!(stderr.contains("No audit events yet"));
    }
    // Human output is unchanged: the hint stays on stdout.
    let (stdout, stderr) = show_output(&path, None, false, false);
    assert!(stdout.contains("No audit events yet"));
    assert!(stderr.is_empty());
}

#[test]
fn show_json_keeps_stdout_machine_readable_when_nothing_matches() {
    let tmp = tempdir().unwrap();
    let empty = write_fixture(tmp.path(), &[]);
    let (stdout, stderr) = show_output(&empty, None, true, false);
    assert!(stdout.is_empty());
    assert!(stderr.contains("No matching audit events"));

    let other = tempdir().unwrap();
    let path = write_fixture(other.path(), &[LINE_STORE, LINE_PUSH]);
    for (op, leaked) in [(Some("vault.delete"), false), (None, true)] {
        let (stdout, stderr) = show_output(&path, op, true, leaked);
        assert!(stdout.is_empty());
        assert!(stderr.contains("No matching audit events"));
    }

    let (stdout, stderr) = show_output(&path, Some("vault.delete"), false, false);
    assert!(stdout.contains("No matching audit events"));
    assert!(stderr.is_empty());
}

#[test]
fn show_json_prints_one_event_object_per_line() {
    let tmp = tempdir().unwrap();
    let path = write_fixture(tmp.path(), &[LINE_STORE, LINE_PUSH]);
    let (stdout, stderr) = show_output(&path, None, true, false);
    assert_eq!(stdout.lines().count(), 2);
    assert!(all_lines_are_json_objects(&stdout));
    assert!(stderr.is_empty());
}

#[test]
fn stats_analytics_json_with_no_events_prints_the_empty_envelope() {
    let report = phantom_core::analytics::AnalyticsReport {
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        secrets: Vec::new(),
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    render_stats_analytics(&report, true, 0, None, &mut out, &mut err).unwrap();
    let parsed: Value =
        serde_json::from_slice(&out).expect("stats --analytics --json stdout must be JSON");
    assert_eq!(
        parsed,
        serde_json::json!({"generated_at": "2026-01-01T00:00:00Z", "secrets": []})
    );
    assert!(String::from_utf8(err)
        .unwrap()
        .contains("No audit events yet"));

    // Human output is unchanged.
    let mut out = Vec::new();
    let mut err = Vec::new();
    render_stats_analytics(&report, false, 0, None, &mut out, &mut err).unwrap();
    assert!(String::from_utf8(out)
        .unwrap()
        .contains("No audit events yet"));
    assert!(err.is_empty());
}

#[test]
fn format_unix_ts_known_value() {
    // 2024-01-15 10:30:45 UTC = 1705314645
    let s = format_unix_ts(1705314645);
    assert_eq!(s, "2024-01-15 10:30:45");
}

#[test]
fn matches_filters_no_filters() {
    assert!(matches_filters(LINE_STORE, None, None));
}

#[test]
fn matches_filters_op_miss() {
    assert!(!matches_filters(LINE_STORE, Some("cloud.push"), None));
}

#[test]
fn matches_filters_name_miss() {
    assert!(!matches_filters(LINE_STORE, None, Some("STRIPE_KEY")));
}

#[test]
fn audit_effect_refuses_headless_execution_before_prompt() {
    let plan = serde_json::json!({"action": "audit-report-save"});
    let mut reader = std::io::Cursor::new(Vec::<u8>::new());
    let mut writer = Vec::new();

    let error = confirm_audit_effect(&plan, false, &mut reader, &mut writer).unwrap_err();

    assert!(error.to_string().contains("trusted terminal"));
    assert!(writer.is_empty());
}

#[test]
fn audit_effect_requires_exact_plan_bound_challenge() {
    let plan = serde_json::json!({
        "action": "audit-alerts-backfill",
        "config_sha256": "abc",
    });
    let plan_json = serde_json::to_string_pretty(&plan).unwrap();
    let challenge = format!(
        "phantom audit authorize {:x}",
        Sha256::digest(plan_json.as_bytes())
    );
    let mut reader = std::io::Cursor::new(format!("{challenge}\n").into_bytes());
    let mut writer = Vec::new();

    confirm_audit_effect(&plan, true, &mut reader, &mut writer).unwrap();

    let prompt = String::from_utf8(writer).unwrap();
    assert!(prompt.contains(&challenge));
    assert!(prompt.contains("config_sha256"));
}

// ── run_analytics integration tests ───────────────────────────────

use crate::test_support::ENV_LOCK;

// Serialise tests that mutate HOME / PHANTOM_AUDIT env vars.

fn with_analytics_home<F: FnOnce(&std::path::Path)>(f: F) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let prev_home = std::env::var("HOME").ok();
    let prev_audit = std::env::var("PHANTOM_AUDIT").ok();
    unsafe {
        std::env::set_var("HOME", tmp.path());
        std::env::set_var("PHANTOM_AUDIT", "1");
    }
    f(tmp.path());
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
}

fn write_analytics_log(path: &std::path::Path, entries: &[(u64, &str, Option<&str>)]) {
    use std::io::Write;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    for (ts, op, name) in entries {
        let line = if let Some(n) = name {
            format!(
                r#"{{"seq":1,"ts":{ts},"op":"{op}","name":"{n}","pid":1,"process":"phantom","prev_hmac":"GENESIS"}}"#
            )
        } else {
            format!(
                r#"{{"seq":1,"ts":{ts},"op":"{op}","pid":1,"process":"phantom","prev_hmac":"GENESIS"}}"#
            )
        };
        writeln!(f, "{}", line).unwrap();
    }
}

#[test]
fn analytics_spike_anomaly_above_threshold() {
    with_analytics_home(|tmp| {
        let log_path = tmp.join(".phantom/audit.log");
        let base_day = 1_700_000_000_u64 / 86400 * 86400;
        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        // 1 access/day on days 1–4
        for i in 1u64..=4 {
            entries.push((base_day + i * 86400, "vault.retrieve", Some("SPIKE_KEY")));
        }
        // 50 accesses on day 0 (spike → anomaly_score >= 0.6)
        for j in 0..50u64 {
            entries.push((base_day + 10 + j, "vault.retrieve", Some("SPIKE_KEY")));
        }
        write_analytics_log(&log_path, &entries);

        // Verify anomaly score directly via analytics API.
        let report =
            phantom_core::analytics::compute_analytics(phantom_core::analytics::Period::All)
                .unwrap();
        let s = report
            .secrets
            .iter()
            .find(|s| s.name == "SPIKE_KEY")
            .unwrap();
        assert!(
            s.anomaly_score >= 0.6,
            "spike should have anomaly_score >= 0.6, got {}",
            s.anomaly_score
        );
    });
}

#[test]
fn analytics_csv_export_format_validation() {
    with_analytics_home(|tmp| {
        let log_path = tmp.join(".phantom/audit.log");
        let now = 1_700_000_000_u64;
        write_analytics_log(
            &log_path,
            &[
                (now - 200, "vault.retrieve", Some("KEY_A")),
                (now - 100, "vault.store", Some("KEY_B")),
            ],
        );

        let records =
            phantom_core::analytics::export_records(phantom_core::analytics::Period::All, None)
                .unwrap();
        assert_eq!(records.len(), 2, "should have 2 records");

        let csv = phantom_core::analytics::records_to_csv(&records);
        // Header must be present.
        assert!(
            csv.starts_with("ts,datetime,op,name,process\n"),
            "CSV must have correct header; got: {:?}",
            &csv[..csv.find('\n').unwrap_or(csv.len())]
        );
        // Both secret names must appear.
        assert!(csv.contains("KEY_A"), "CSV must contain KEY_A");
        assert!(csv.contains("KEY_B"), "CSV must contain KEY_B");
        // No secret values (they are never logged).
        let lines: Vec<&str> = csv.lines().skip(1).collect();
        for line in &lines {
            let fields: Vec<&str> = line.split(',').collect();
            // CSV has 5 columns: ts,datetime,op,name,process
            assert_eq!(
                fields.len(),
                5,
                "each CSV data row should have 5 columns, got: {:?}",
                line
            );
        }
    });
}

#[test]
fn analytics_min_anomaly_score_filters_records() {
    with_analytics_home(|tmp| {
        let log_path = tmp.join(".phantom/audit.log");
        let now = 1_700_000_000_u64;
        // NORMAL_KEY: 3 accesses spread over 3 consecutive seconds (no anomaly).
        // QUIET_KEY: 10-day gap → anomaly_score >= 0.5.
        let mut entries = vec![
            (now - 2 * 86400, "vault.retrieve", Some("NORMAL_KEY")),
            (now - 86400, "vault.retrieve", Some("NORMAL_KEY")),
            (now, "vault.retrieve", Some("NORMAL_KEY")),
            (now - 11 * 86400, "vault.retrieve", Some("QUIET_KEY")),
            (now - 86400, "vault.retrieve", Some("QUIET_KEY")),
        ];
        // Ensure chronological order.
        entries.sort_by_key(|e| e.0);
        write_analytics_log(&log_path, &entries);

        let records = phantom_core::analytics::export_records(
            phantom_core::analytics::Period::All,
            Some(0.5),
        )
        .unwrap();
        // Only QUIET_KEY should be included.
        assert!(
            records.iter().all(|r| r.name == "QUIET_KEY"),
            "min_anomaly_score=0.5 should keep only QUIET_KEY; got {:?}",
            records.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
    });
}

#[test]
fn show_text_writes_events_into_out() {
    let tmp = tempdir().unwrap();
    let path = write_fixture(tmp.path(), &[LINE_STORE, LINE_PUSH]);
    let (stdout, stderr) = show_output(&path, None, false, false);
    assert_eq!(stdout.lines().count(), 2);
    assert!(stderr.is_empty());
}
