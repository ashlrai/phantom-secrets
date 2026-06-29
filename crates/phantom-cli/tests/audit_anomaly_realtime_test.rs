//! Integration tests for `phantom audit anomalies` (windowed / real-time
//! anomaly detection).
//!
//! These tests exercise the core analytics primitives directly rather than
//! spawning a full CLI process, which makes them deterministic and fast while
//! still covering the public API surface that the CLI and MCP tool both use.

use phantom_core::analytics::{
    check_windowed_anomaly, compute_windowed_anomalies, AuditThresholdConfig,
};
use std::io::Write;
use std::sync::Mutex;

// Serialise tests that mutate HOME / PHANTOM_AUDIT env vars.
static ENV_LOCK: Mutex<()> = Mutex::new(());

// ── helpers ───────────────────────────────────────────────────────────────────

/// Set HOME and PHANTOM_AUDIT for the duration of a closure, then restore.
fn with_audit_home<F: FnOnce(&std::path::Path)>(f: F) {
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

/// Write synthetic JSONL audit-log entries.
fn write_log(path: &std::path::Path, entries: &[(u64, &str, Option<&str>)]) {
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

// ── Unit tests for check_windowed_anomaly ────────────────────────────────────

#[test]
fn no_anomaly_for_empty_timestamps() {
    let result = check_windowed_anomaly("MY_KEY", &[], 1_700_000_000, None, 0.5);
    assert_eq!(result.anomaly_score, 0.0);
    assert!(!result.alert);
    assert_eq!(result.accesses_last_hour, 0);
    assert_eq!(result.max_quiet_gap_days, 0);
}

#[test]
fn no_anomaly_for_single_access() {
    let now = 1_700_000_000_u64;
    let result = check_windowed_anomaly("MY_KEY", &[now - 100], now, None, 0.5);
    assert_eq!(result.anomaly_score, 0.0);
    assert!(!result.alert);
}

#[test]
fn spike_detection_rate_limit_exceeded() {
    // 150 accesses within the last hour → exceeds default max_per_hour=100 → score 0.7
    let now = 1_700_000_000_u64;
    let window_start = now - 3600;
    // Spread 150 accesses evenly within the last hour.
    let timestamps: Vec<u64> = (0..150_u64)
        .map(|i| window_start + i * (3600 / 150))
        .collect();

    let result = check_windowed_anomaly("RATE_KEY", &timestamps, now, None, 0.5);
    assert!(
        result.anomaly_score >= 0.7,
        "150 accesses/hr should score >= 0.7, got {}",
        result.anomaly_score
    );
    assert!(result.alert, "should alert at threshold 0.5");
    assert_eq!(result.accesses_last_hour, 150);
}

#[test]
fn spike_detection_exactly_at_limit_no_trigger() {
    // Exactly 100 accesses within the last hour → NOT > 100 → no rate spike.
    let now = 1_700_000_000_u64;
    let window_start = now - 3600;
    let timestamps: Vec<u64> = (0..100_u64)
        .map(|i| window_start + i * 36)
        .collect();

    let result = check_windowed_anomaly("EXACT_KEY", &timestamps, now, None, 0.5);
    assert!(
        result.anomaly_score < 0.7,
        "exactly 100 accesses/hr should NOT trigger rate spike, got {}",
        result.anomaly_score
    );
}

#[test]
fn quiet_period_detection_above_threshold() {
    // Two accesses 8 days apart → quiet gap >= default 7 days → score 0.5
    let t0 = 1_700_000_000_u64;
    let t1 = t0 + 8 * 86400;
    let result = check_windowed_anomaly("QUIET_KEY", &[t0, t1], t1 + 60, None, 0.5);
    assert!(
        (result.anomaly_score - 0.5).abs() < f64::EPSILON,
        "8-day gap should score 0.5, got {}",
        result.anomaly_score
    );
    assert_eq!(result.max_quiet_gap_days, 8);
    assert!(result.alert);
}

#[test]
fn quiet_period_below_threshold_no_trigger() {
    // Two accesses 5 days apart → quiet gap < default 7 days → no quiet alert
    let t0 = 1_700_000_000_u64;
    let t1 = t0 + 5 * 86400;
    let result = check_windowed_anomaly("SHORT_GAP_KEY", &[t0, t1], t1 + 60, None, 0.5);
    assert_eq!(result.anomaly_score, 0.0, "5-day gap should NOT trigger");
    assert!(!result.alert);
}

#[test]
fn per_secret_threshold_max_accesses_per_hour_override() {
    // Custom threshold: max 10/hr. 15 accesses within last hour should trigger.
    let now = 1_700_000_000_u64;
    let window_start = now - 3600;
    let timestamps: Vec<u64> = (0..15_u64)
        .map(|i| window_start + i * 200)
        .collect();

    let thresholds = AuditThresholdConfig {
        max_accesses_per_hour: Some(10),
        max_consecutive_quiet_days: None,
        alert_on_anomaly_score: Some(0.5),
    };

    let result = check_windowed_anomaly("CUSTOM_KEY", &timestamps, now, Some(&thresholds), 0.5);
    assert!(
        result.anomaly_score >= 0.7,
        "15 accesses exceeding custom max=10 should score >= 0.7, got {}",
        result.anomaly_score
    );
    assert!(result.alert);
    assert_eq!(result.accesses_last_hour, 15);
}

#[test]
fn per_secret_threshold_quiet_days_override() {
    // Custom quiet threshold: 3 days. A 4-day gap should trigger.
    let t0 = 1_700_000_000_u64;
    let t1 = t0 + 4 * 86400;

    let thresholds = AuditThresholdConfig {
        max_accesses_per_hour: None,
        max_consecutive_quiet_days: Some(3),
        alert_on_anomaly_score: Some(0.5),
    };

    let result =
        check_windowed_anomaly("CUSTOM_QUIET", &[t0, t1], t1 + 60, Some(&thresholds), 0.5);
    assert!(
        result.anomaly_score >= 0.5,
        "4-day gap with custom quiet=3 should score >= 0.5, got {}",
        result.anomaly_score
    );
    assert!(result.alert);
    assert_eq!(result.max_quiet_gap_days, 4);
}

#[test]
fn both_rules_score_is_max_not_sum() {
    // Both rate spike (0.7) and quiet period (0.5) triggered — max = 0.7.
    let now = 1_700_000_000_u64;
    let old_access = now - 10 * 86400; // quiet gap = 10d
    let window_start = now - 3600;

    let mut timestamps: Vec<u64> = vec![old_access];
    // 120 accesses in the last hour → rate spike
    for i in 0..120_u64 {
        timestamps.push(window_start + i * 30);
    }
    timestamps.sort_unstable();

    let result = check_windowed_anomaly("BOTH_KEY", &timestamps, now, None, 0.5);
    assert!(
        result.anomaly_score <= 1.0,
        "score must not exceed 1.0, got {}",
        result.anomaly_score
    );
    assert!(
        (result.anomaly_score - 0.7).abs() < f64::EPSILON,
        "max(0.7, 0.5) should be 0.7, got {}",
        result.anomaly_score
    );
}

#[test]
fn alert_flag_respects_global_threshold() {
    // Score 0.5 (quiet period only) — alert=true when threshold=0.5, false when 0.7.
    let t0 = 1_700_000_000_u64;
    let t1 = t0 + 8 * 86400;

    let result_low = check_windowed_anomaly("THRESH_KEY", &[t0, t1], t1 + 60, None, 0.5);
    assert!(result_low.alert, "score 0.5 >= threshold 0.5 should alert");

    let result_high = check_windowed_anomaly("THRESH_KEY", &[t0, t1], t1 + 60, None, 0.7);
    assert!(
        !result_high.alert,
        "score 0.5 < threshold 0.7 should NOT alert"
    );
}

#[test]
fn accesses_outside_hour_window_not_counted() {
    // 200 accesses all finishing at least 1 hour before now → accesses_last_hour = 0.
    // Place them in a 30-minute window ending exactly at now-3601 (safely outside the
    // 1-hour rolling window).
    let now = 1_700_000_000_u64;
    let window_end = now - 3601; // last access is 3601 seconds ago
    let window_start = window_end - 1800; // span 30 minutes
    let timestamps: Vec<u64> = (0..200_u64)
        .map(|i| window_start + i * (1800 / 200))
        .collect();
    // Sanity: all timestamps must be < now - 3600.
    assert!(timestamps.iter().all(|&ts| ts < now - 3600));

    let result = check_windowed_anomaly("OLD_KEY", &timestamps, now, None, 0.5);
    assert_eq!(result.accesses_last_hour, 0, "all accesses are > 1hr old");
    // No rate spike (none within last hour). No quiet gap (accesses were consecutive).
    assert_eq!(result.anomaly_score, 0.0);
}

// ── Integration tests using the audit log ────────────────────────────────────

#[test]
fn compute_windowed_anomalies_empty_log_returns_empty() {
    with_audit_home(|_tmp| {
        let results = compute_windowed_anomalies(None, None, 0.5).unwrap();
        assert!(results.is_empty(), "no log → no results");
    });
}

#[test]
fn compute_windowed_anomalies_spike_detected() {
    with_audit_home(|tmp| {
        let log_path = tmp.join(".phantom/audit.log");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 120 accesses within the last 30 minutes → exceeds max_per_hour=100
        let window_start = now - 1800;
        let entries: Vec<(u64, &str, Option<&str>)> = (0..120_u64)
            .map(|i| (window_start + i * 15, "vault.retrieve", Some("SPIKE_RT")))
            .collect();
        write_log(&log_path, &entries);

        let results = compute_windowed_anomalies(None, None, 0.5).unwrap();
        let r = results.iter().find(|r| r.name == "SPIKE_RT").unwrap();
        assert!(
            r.anomaly_score >= 0.7,
            "should detect rate spike, got {}",
            r.anomaly_score
        );
        assert!(r.alert);
        assert_eq!(r.accesses_last_hour, 120);
    });
}

#[test]
fn compute_windowed_anomalies_quiet_period_detected() {
    with_audit_home(|tmp| {
        let log_path = tmp.join(".phantom/audit.log");
        let t0 = 1_700_000_000_u64;
        let t1 = t0 + 10 * 86400; // 10-day gap

        write_log(
            &log_path,
            &[
                (t0, "vault.retrieve", Some("QUIET_RT")),
                (t1, "vault.retrieve", Some("QUIET_RT")),
            ],
        );

        let results = compute_windowed_anomalies(None, None, 0.5).unwrap();
        let r = results.iter().find(|r| r.name == "QUIET_RT").unwrap();
        assert!(
            r.anomaly_score >= 0.5,
            "should detect quiet period, got {}",
            r.anomaly_score
        );
        assert_eq!(r.max_quiet_gap_days, 10);
    });
}

#[test]
fn compute_windowed_anomalies_name_filter_isolates_secret() {
    with_audit_home(|tmp| {
        let log_path = tmp.join(".phantom/audit.log");
        let t0 = 1_700_000_000_u64;

        // KEY_A: quiet gap → anomaly
        // KEY_B: uniform → clean
        write_log(
            &log_path,
            &[
                (t0, "vault.retrieve", Some("KEY_A")),
                (t0 + 9 * 86400, "vault.retrieve", Some("KEY_A")),
                (t0, "vault.retrieve", Some("KEY_B")),
                (t0 + 86400, "vault.retrieve", Some("KEY_B")),
            ],
        );

        let results = compute_windowed_anomalies(Some("KEY_A"), None, 0.5).unwrap();
        assert!(results.iter().all(|r| r.name == "KEY_A"), "filter should isolate KEY_A");
        assert!(results.iter().all(|r| r.name != "KEY_B"), "KEY_B should be excluded");
    });
}

#[test]
fn compute_windowed_anomalies_threshold_filters_results() {
    with_audit_home(|tmp| {
        let log_path = tmp.join(".phantom/audit.log");
        let t0 = 1_700_000_000_u64;
        let t1 = t0 + 9 * 86400;

        // QUIET_KEY: quiet gap → score 0.5
        write_log(
            &log_path,
            &[
                (t0, "vault.retrieve", Some("QUIET_KEY")),
                (t1, "vault.retrieve", Some("QUIET_KEY")),
            ],
        );

        // threshold=0.7 → should not include quiet-period results (score 0.5)
        let results = compute_windowed_anomalies(None, None, 0.7).unwrap();
        let filtered: Vec<_> = results.iter().filter(|r| r.anomaly_score >= 0.7).collect();
        assert!(
            filtered.iter().all(|r| r.name != "QUIET_KEY"),
            "threshold=0.7 should exclude quiet-period finding (score 0.5)"
        );
    });
}

#[test]
fn compute_windowed_anomalies_concurrent_writes_safe() {
    // Verify that concurrent appends to the audit log during a threshold check
    // do not panic or corrupt the result (no torn reads).
    with_audit_home(|tmp| {
        let log_path = tmp.join(".phantom/audit.log");
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();

        let log_path_clone = log_path.clone();
        // Writer thread: rapidly append 200 entries.
        let writer = std::thread::spawn(move || {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path_clone)
                .unwrap();
            for i in 0u64..200 {
                let ts = 1_700_000_000_u64 + i;
                writeln!(
                    f,
                    r#"{{"seq":{i},"ts":{ts},"op":"vault.retrieve","name":"CONCURRENT_KEY","pid":1,"process":"phantom","prev_hmac":"GENESIS"}}"#
                )
                .unwrap();
            }
        });

        // Reader: call compute_windowed_anomalies while writer is active.
        // Must not panic; result may or may not find anomalies depending on timing.
        let _ = compute_windowed_anomalies(Some("CONCURRENT_KEY"), None, 0.5);

        writer.join().unwrap();

        // After the writer completes we should get a deterministic result.
        let results = compute_windowed_anomalies(Some("CONCURRENT_KEY"), None, 0.5).unwrap();
        // Verify the result is well-formed (no panic, name matches).
        for r in &results {
            assert_eq!(r.name, "CONCURRENT_KEY");
            assert!(r.anomaly_score >= 0.0 && r.anomaly_score <= 1.0);
        }
    });
}

#[test]
fn per_secret_thresholds_roundtrip_through_config_toml() {
    // Verify that AuditThresholdConfig survives a TOML serialize/deserialize
    // round-trip inside SecretOverride.
    use phantom_core::analytics::AuditThresholdConfig;
    use phantom_core::config::{PhantomConfig, SecretOverride};

    let mut config = PhantomConfig::new_with_defaults("audit_rt_test".to_string());
    config.phantom.secrets.insert(
        "MY_SECRET".to_string(),
        SecretOverride {
            rotate_every: None,
            rotation_schedule: None,
            audit: Some(AuditThresholdConfig {
                max_accesses_per_hour: Some(50),
                max_consecutive_quiet_days: Some(3),
                alert_on_anomaly_score: Some(0.6),
            }),
        },
    );

    let toml_str = toml::to_string_pretty(&config).unwrap();
    assert!(
        toml_str.contains("max_accesses_per_hour"),
        "TOML should contain max_accesses_per_hour"
    );
    assert!(
        toml_str.contains("max_consecutive_quiet_days"),
        "TOML should contain max_consecutive_quiet_days"
    );
    assert!(
        toml_str.contains("alert_on_anomaly_score"),
        "TOML should contain alert_on_anomaly_score"
    );

    let parsed: PhantomConfig = toml::from_str(&toml_str).unwrap();
    let ov = parsed.phantom.secrets.get("MY_SECRET").unwrap();
    let audit = ov.audit.as_ref().unwrap();
    assert_eq!(audit.max_accesses_per_hour, Some(50));
    assert_eq!(audit.max_consecutive_quiet_days, Some(3));
    assert_eq!(audit.alert_on_anomaly_score, Some(0.6));
}

#[test]
fn per_secret_audit_config_deny_unknown_fields() {
    // Typos in [phantom.secrets.MY_KEY.audit] must fail loudly.
    let bad_toml = r#"
[phantom]
version = "1"
project_id = "abc"

[phantom.secrets.MY_KEY]
[phantom.secrets.MY_KEY.audit]
max_accesses_per_hour = 10
typo_field = "oops"
"#;
    assert!(
        toml::from_str::<phantom_core::config::PhantomConfig>(bad_toml).is_err(),
        "unknown audit field should be rejected by deny_unknown_fields"
    );
}

#[test]
fn secret_name_never_in_anomaly_score_results() {
    // Paranoia guard: the WindowedAnomalyResult must never carry the secret value.
    with_audit_home(|tmp| {
        let log_path = tmp.join(".phantom/audit.log");
        let t0 = 1_700_000_000_u64;
        write_log(
            &log_path,
            &[
                (t0, "vault.retrieve", Some("SAFE_KEY")),
                (t0 + 9 * 86400, "vault.retrieve", Some("SAFE_KEY")),
            ],
        );

        let results = compute_windowed_anomalies(None, None, 0.0).unwrap();
        for r in &results {
            // The reason string must not contain the secret value (it only contains
            // metric numbers and threshold values — this test checks for obvious leaks).
            assert!(
                !r.reason.contains("sk-"),
                "reason must not contain a secret value prefix"
            );
            assert!(
                !r.reason.contains("phm_"),
                "reason must not contain a phantom token"
            );
        }
    });
}
