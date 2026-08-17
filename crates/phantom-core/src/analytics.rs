//! Audit log analytics and anomaly detection.
//!
//! This module builds on the raw per-second access counts in [`crate::audit`]
//! to compute daily-bucket statistics and flag anomalous access patterns.
//!
//! ## Anomaly scoring
//!
//! Two rules contribute to an anomaly score in the range [0.0, 1.0]:
//!
//! | Rule | Score |
//! |------|-------|
//! | Any single day has > 3× the overall `daily_avg` | 0.6 |
//! | First access after ≥ 7 consecutive quiet days | 0.5 |
//!
//! Multiple rules combine by taking the **max** of individual scores (no
//! double-counting). A caller can filter results with `--min-anomaly-score`.
//!
//! ## Export
//!
//! [`export_records`] returns a `Vec<AccessRecord>` (one entry per log line
//! that names a secret and falls within the requested period). The caller
//! drives CSV or JSON serialisation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::Path;

// ──────────────────────────────────────────────────────────────────────────────
// Per-secret audit threshold configuration
// ──────────────────────────────────────────────────────────────────────────────

/// Per-secret anomaly thresholds stored under
/// `[phantom.secrets.{name}.audit]` in `.phantom.toml`.
///
/// All fields are optional; defaults are applied when absent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuditThresholdConfig {
    /// Maximum allowed accesses within any rolling 1-hour window.
    /// Exceeding this contributes a score of 0.7 (override-spike).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_accesses_per_hour: Option<u64>,
    /// If the secret has been quiet for this many consecutive days and is then
    /// accessed, score 0.5 (quiet-period). Defaults to 7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_consecutive_quiet_days: Option<u64>,
    /// Minimum anomaly score at which an alert is emitted (0.0–1.0).
    /// Defaults to 0.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_on_anomaly_score: Option<f64>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Windowed anomaly detection result
// ──────────────────────────────────────────────────────────────────────────────

/// Result of a windowed / real-time anomaly check for a single secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowedAnomalyResult {
    /// Secret name (never the value).
    pub name: String,
    /// Computed anomaly score in [0.0, 1.0].
    pub anomaly_score: f64,
    /// Human-readable reason string (empty when score == 0.0).
    pub reason: String,
    /// Whether this result should trigger an alert given the configured
    /// `alert_on_anomaly_score` (or the supplied `threshold` argument).
    pub alert: bool,
    /// Accesses observed within the most recent 1-hour window.
    pub accesses_last_hour: u64,
    /// Length of the longest consecutive quiet period (days) ending at the
    /// most recent access.
    pub max_quiet_gap_days: u64,
}

/// Check recent audit-log events for a single secret against per-second
/// windowed thresholds.
///
/// `now_ts` – current Unix epoch seconds (allows deterministic testing).
/// `thresholds` – per-secret config loaded from `.phantom.toml`; pass
///   `None` to use built-in defaults.
/// `global_threshold` – additional alert gate; if the computed score ≥
///   this value `alert` is set to `true`.
pub fn check_windowed_anomaly(
    name: &str,
    timestamps: &[u64],
    now_ts: u64,
    thresholds: Option<&AuditThresholdConfig>,
    global_threshold: f64,
) -> WindowedAnomalyResult {
    let max_per_hour = thresholds
        .and_then(|t| t.max_accesses_per_hour)
        .unwrap_or(100);
    let quiet_days = thresholds
        .and_then(|t| t.max_consecutive_quiet_days)
        .unwrap_or(7);
    let alert_score = thresholds
        .and_then(|t| t.alert_on_anomaly_score)
        .unwrap_or(0.5)
        .clamp(0.0, 1.0);

    // Accesses within the last 3600 seconds.
    let window_start = now_ts.saturating_sub(3600);
    let accesses_last_hour = timestamps.iter().filter(|&&ts| ts >= window_start).count() as u64;

    // Longest quiet gap (days) among consecutive sorted pairs.
    let max_quiet_gap_days: u64 = if timestamps.len() >= 2 {
        let mut sorted = timestamps.to_vec();
        sorted.sort_unstable();
        sorted
            .windows(2)
            .map(|w| w[1].saturating_sub(w[0]) / 86400)
            .max()
            .unwrap_or(0)
    } else {
        0
    };

    let mut score: f64 = 0.0;
    let mut reasons: Vec<String> = Vec::new();

    // Rule 1: per-hour rate exceeded.
    if accesses_last_hour > max_per_hour {
        score = score.max(0.7);
        reasons.push(format!(
            "accesses_last_hour={accesses_last_hour} exceeds max_accesses_per_hour={max_per_hour}"
        ));
    }

    // Rule 2: re-access after a quiet period.
    if max_quiet_gap_days >= quiet_days {
        score = score.max(0.5);
        reasons.push(format!(
            "quiet_gap={max_quiet_gap_days}d >= max_consecutive_quiet_days={quiet_days}d"
        ));
    }

    let score = score.clamp(0.0, 1.0);
    // Alert fires when the score meets BOTH the per-secret config threshold AND
    // the caller-supplied global_threshold (use the higher of the two as the gate).
    let effective_alert_score = alert_score.max(global_threshold);
    let alert = score >= effective_alert_score && score > 0.0;

    WindowedAnomalyResult {
        name: name.to_string(),
        anomaly_score: score,
        reason: reasons.join("; "),
        alert,
        accesses_last_hour,
        max_quiet_gap_days,
    }
}

/// Convenience wrapper: read the audit log and compute `WindowedAnomalyResult`
/// for a specific secret (or all secrets when `name_filter` is `None`).
///
/// Returns an empty `Vec` when the audit log does not exist.
pub fn compute_windowed_anomalies(
    name_filter: Option<&str>,
    thresholds: Option<&AuditThresholdConfig>,
    global_threshold: f64,
) -> std::io::Result<Vec<WindowedAnomalyResult>> {
    let path = crate::audit::log_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }

    let now = now_unix();
    let raw = read_events_from_path(&path, 0)?;

    // Group by name.
    let mut by_name: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for ev in raw {
        if let Some(n) = ev.name {
            if name_filter.is_none_or(|f| f == n) {
                by_name.entry(n).or_default().push(ev.ts);
            }
        }
    }

    let mut results: Vec<WindowedAnomalyResult> = by_name
        .into_iter()
        .map(|(name, mut ts)| {
            ts.sort_unstable();
            check_windowed_anomaly(&name, &ts, now, thresholds, global_threshold)
        })
        .collect();

    // Highest score first.
    results.sort_by(|a, b| {
        b.anomaly_score
            .partial_cmp(&a.anomaly_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.name.cmp(&b.name))
    });

    Ok(results)
}

// ──────────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────────

/// Extended per-secret statistics including daily-bucket analytics and an
/// anomaly score. This is the element type of the JSON returned by
/// `phantom audit stats` and the `phantom_audit_stats` MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAnalytics {
    /// Secret name (never the value).
    pub name: String,
    /// Total number of logged access operations for this secret.
    pub access_count: u64,
    /// Unix timestamp of the most recent access (0 = no timestamped events).
    pub last_access: u64,
    /// Average accesses per day across the observed window (rounded to 2 dp).
    pub daily_avg: f64,
    /// Highest single-day access count observed.
    pub max_daily: u64,
    /// Lowest single-day access count observed (for days with ≥ 1 access).
    pub min_daily: u64,
    /// Anomaly score in [0.0, 1.0]. 0.0 = no anomaly detected.
    pub anomaly_score: f64,
}

/// The top-level JSON envelope returned by `phantom audit stats --analytics`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalyticsReport {
    /// ISO-8601 generation timestamp (UTC, seconds precision).
    pub generated_at: String,
    /// Per-secret analytics, sorted by anomaly_score descending then name.
    pub secrets: Vec<SecretAnalytics>,
}

/// A single timestamped access record used for CSV / JSON export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRecord {
    /// Unix timestamp of the event.
    pub ts: u64,
    /// ISO-8601 datetime string (UTC).
    pub datetime: String,
    /// Operation name (e.g. `vault.retrieve`).
    pub op: String,
    /// Secret name. Never contains the secret value.
    pub name: String,
    /// Process name that performed the operation.
    pub process: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Period
// ──────────────────────────────────────────────────────────────────────────────

/// Selects how far back to look when building analytics or exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    Days7,
    Days30,
    /// All available history.
    All,
}

impl Period {
    /// Parse `"7d"` or `"30d"`.
    pub fn parse(s: &str) -> Option<Period> {
        match s {
            "7d" => Some(Period::Days7),
            "30d" => Some(Period::Days30),
            "all" => Some(Period::All),
            _ => None,
        }
    }

    /// Minimum Unix timestamp for events to be included (0 = no cutoff).
    pub fn cutoff_ts(self) -> u64 {
        let now = now_unix();
        match self {
            Period::Days7 => now.saturating_sub(7 * 86400),
            Period::Days30 => now.saturating_sub(30 * 86400),
            Period::All => 0,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Core analytics
// ──────────────────────────────────────────────────────────────────────────────

/// Read `~/.phantom/audit.log` and compute per-secret analytics with anomaly
/// detection for the given `period`.
///
/// Returns `Ok(AnalyticsReport)` even when the log file does not exist.
pub fn compute_analytics(period: Period) -> std::io::Result<AnalyticsReport> {
    let path = crate::audit::log_path()?;

    if !path.exists() {
        return Ok(AnalyticsReport {
            generated_at: iso8601_now(),
            secrets: vec![],
        });
    }

    let cutoff = period.cutoff_ts();
    let raw = read_events_from_path(&path, cutoff)?;
    let report = build_report(raw);
    Ok(report)
}

/// Read all access events from `path` that are at or after `cutoff_ts`.
/// Skips marker lines, malformed JSON, and lines without `op`.
fn read_events_from_path(path: &Path, cutoff_ts: u64) -> std::io::Result<Vec<RawEvent>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Skip chain marker lines.
        if v.get("hmac_chain_started_at").is_some() {
            continue;
        }
        let op = match v.get("op").and_then(|o| o.as_str()) {
            Some(op) => op.to_string(),
            None => continue,
        };
        let ts = v.get("ts").and_then(|t| t.as_u64()).unwrap_or(0);
        if ts < cutoff_ts {
            continue;
        }
        let name = v
            .get("name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());
        let process = v
            .get("process")
            .and_then(|p| p.as_str())
            .unwrap_or("phantom")
            .to_string();

        events.push(RawEvent {
            ts,
            op,
            name,
            process,
        });
    }

    Ok(events)
}

/// Build the analytics report from raw events.
fn build_report(events: Vec<RawEvent>) -> AnalyticsReport {
    // Group by secret name — only events that carry a name contribute.
    // BTreeMap<name, Vec<ts>>
    let mut by_name: BTreeMap<String, Vec<u64>> = BTreeMap::new();

    for ev in &events {
        if let Some(ref name) = ev.name {
            by_name.entry(name.clone()).or_default().push(ev.ts);
        }
    }

    let mut analytics: Vec<SecretAnalytics> = by_name
        .into_iter()
        .map(|(name, mut timestamps)| {
            timestamps.sort_unstable();
            compute_secret_analytics(name, &timestamps)
        })
        .collect();

    // Sort: highest anomaly score first, then alphabetically.
    analytics.sort_by(|a, b| {
        b.anomaly_score
            .partial_cmp(&a.anomaly_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.name.cmp(&b.name))
    });

    AnalyticsReport {
        generated_at: iso8601_now(),
        secrets: analytics,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-secret computation
// ──────────────────────────────────────────────────────────────────────────────

/// Compute analytics for a single secret given its sorted list of timestamps.
fn compute_secret_analytics(name: String, timestamps: &[u64]) -> SecretAnalytics {
    let access_count = timestamps.len() as u64;
    let last_access = timestamps.last().copied().unwrap_or(0);
    let first_access = timestamps.first().copied().unwrap_or(0);

    // Bucket events into calendar days (UTC, day = ts / 86400).
    let mut daily: BTreeMap<u64, u64> = BTreeMap::new();
    for &ts in timestamps {
        let day = ts / 86400;
        *daily.entry(day).or_insert(0) += 1;
    }

    let max_daily = daily.values().copied().max().unwrap_or(0);
    let min_daily = daily.values().copied().min().unwrap_or(0);

    // daily_avg = total accesses / span in days (at least 1).
    let span_days = if last_access > first_access {
        ((last_access - first_access) as f64 / 86400.0)
            .ceil()
            .max(1.0)
    } else {
        1.0
    };
    let daily_avg = (access_count as f64) / span_days;
    // Round to 2 decimal places.
    let daily_avg = (daily_avg * 100.0).round() / 100.0;

    let anomaly_score = compute_anomaly_score(&daily, daily_avg, timestamps);

    SecretAnalytics {
        name,
        access_count,
        last_access,
        daily_avg,
        max_daily,
        min_daily,
        anomaly_score,
    }
}

/// Compute anomaly score for a secret.
///
/// Rules:
/// 1. Any single day has > 3× the overall `daily_avg` → score 0.6
/// 2. First access (or re-access) after ≥ 7 consecutive quiet days → score 0.5
///
/// Result = max of triggered rule scores (range [0.0, 1.0]).
fn compute_anomaly_score(daily: &BTreeMap<u64, u64>, daily_avg: f64, timestamps: &[u64]) -> f64 {
    let mut score: f64 = 0.0;

    // Rule 1: spike detection — any day with count > 3× daily_avg.
    if daily_avg > 0.0 {
        for &count in daily.values() {
            if count as f64 > 3.0 * daily_avg {
                score = score.max(0.6);
                break;
            }
        }
    }

    // Rule 2: re-emergence after ≥ 7 quiet days.
    // Walk sorted timestamps and look for a gap ≥ 7 * 86400 seconds.
    if timestamps.len() >= 2 {
        let quiet_threshold = 7 * 86400_u64;
        for w in timestamps.windows(2) {
            let gap = w[1].saturating_sub(w[0]);
            if gap >= quiet_threshold {
                score = score.max(0.5);
                break;
            }
        }
    }

    // Clamp to [0.0, 1.0] for safety.
    score.clamp(0.0, 1.0)
}

// ──────────────────────────────────────────────────────────────────────────────
// Export
// ──────────────────────────────────────────────────────────────────────────────

/// Read `~/.phantom/audit.log` and return timestamped access records for the
/// given period, optionally filtered to only include records whose secret has
/// an anomaly score ≥ `min_anomaly_score`.
///
/// The returned records are sorted by `ts` ascending.
pub fn export_records(
    period: Period,
    min_anomaly_score: Option<f64>,
) -> std::io::Result<Vec<AccessRecord>> {
    let path = crate::audit::log_path()?;

    if !path.exists() {
        return Ok(vec![]);
    }

    let cutoff = period.cutoff_ts();
    let raw = read_events_from_path(&path, cutoff)?;

    // If min_anomaly_score is set, first compute analytics to get scores.
    let allowed_names: Option<std::collections::HashSet<String>> =
        if let Some(min_score) = min_anomaly_score {
            let report = build_report(raw.clone());
            Some(
                report
                    .secrets
                    .into_iter()
                    .filter(|s| s.anomaly_score >= min_score)
                    .map(|s| s.name)
                    .collect(),
            )
        } else {
            None
        };

    let mut records: Vec<AccessRecord> = raw
        .into_iter()
        .filter_map(|ev| {
            let name = ev.name?; // skip events without a name
            if let Some(ref allowed) = allowed_names {
                if !allowed.contains(&name) {
                    return None;
                }
            }
            Some(AccessRecord {
                datetime: unix_to_iso8601(ev.ts),
                ts: ev.ts,
                op: ev.op,
                name,
                process: ev.process,
            })
        })
        .collect();

    records.sort_by_key(|r| r.ts);
    Ok(records)
}

/// Render a `Vec<AccessRecord>` as RFC 4180 CSV (header + data rows).
/// Returns the full CSV string.
pub fn records_to_csv(records: &[AccessRecord]) -> String {
    let mut out = String::from("ts,datetime,op,name,process\n");
    for r in records {
        // CSV-escape: wrap in double-quotes if the field contains comma/quote/newline.
        let name = csv_escape(&r.name);
        let op = csv_escape(&r.op);
        let process = csv_escape(&r.process);
        let dt = csv_escape(&r.datetime);
        out.push_str(&format!("{},{},{},{},{}\n", r.ts, dt, op, name, process));
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct RawEvent {
    ts: u64,
    op: String,
    name: Option<String>,
    process: String,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn iso8601_now() -> String {
    unix_to_iso8601(now_unix())
}

/// Format a Unix epoch (seconds) as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn unix_to_iso8601(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hh, mm, ss
    )
}

/// Convert days-since-Unix-epoch to (year, month, day).
/// Algorithm: http://howardhinnant.github.io/date_algorithms.html
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ENV_LOCK;

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

    /// Write synthetic audit log entries directly to the log file.
    fn write_synthetic_log(path: &std::path::Path, entries: &[(u64, &str, Option<&str>)]) {
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

    // ── Period ────────────────────────────────────────────────────────────────

    #[test]
    fn period_parse_roundtrip() {
        assert_eq!(Period::parse("7d"), Some(Period::Days7));
        assert_eq!(Period::parse("30d"), Some(Period::Days30));
        assert_eq!(Period::parse("all"), Some(Period::All));
        assert_eq!(Period::parse("invalid"), None);
    }

    #[test]
    fn period_all_cutoff_is_zero() {
        assert_eq!(Period::All.cutoff_ts(), 0);
    }

    #[test]
    fn period_7d_cutoff_is_approximately_7_days_ago() {
        let now = now_unix();
        let cutoff = Period::Days7.cutoff_ts();
        let diff = now.saturating_sub(cutoff);
        // Should be within 1s of 7 days
        assert!((diff as i64 - 7 * 86400).abs() <= 1, "diff={diff}");
    }

    // ── Anomaly detection ─────────────────────────────────────────────────────

    #[test]
    fn no_anomaly_for_uniform_access_pattern() {
        // 3 accesses spread evenly over 3 days — no anomaly expected.
        let day0: u64 = 1_700_000_000 / 86400 * 86400;
        let timestamps = vec![day0, day0 + 86400, day0 + 2 * 86400];
        let mut daily: BTreeMap<u64, u64> = BTreeMap::new();
        for &ts in &timestamps {
            *daily.entry(ts / 86400).or_insert(0) += 1;
        }
        let daily_avg = 1.0;
        let score = compute_anomaly_score(&daily, daily_avg, &timestamps);
        assert_eq!(score, 0.0, "uniform pattern should have score 0.0");
    }

    #[test]
    fn spike_rule_triggers_on_3x_daily_avg() {
        // avg = 2.0, day 0 has 7 accesses (> 3×2=6)
        let day0: u64 = 1_700_000_000 / 86400 * 86400;
        let timestamps: Vec<u64> = std::iter::repeat_n(day0, 7).collect();
        let mut daily: BTreeMap<u64, u64> = BTreeMap::new();
        for &ts in &timestamps {
            *daily.entry(ts / 86400).or_insert(0) += 1;
        }
        let daily_avg = 2.0;
        let score = compute_anomaly_score(&daily, daily_avg, &timestamps);
        assert!(
            (score - 0.6).abs() < f64::EPSILON,
            "spike should score 0.6, got {score}"
        );
    }

    #[test]
    fn spike_rule_does_not_trigger_at_exactly_3x() {
        // avg = 2.0, day 0 has exactly 6 accesses (= 3×2, not strictly ">")
        let day0: u64 = 1_700_000_000 / 86400 * 86400;
        let timestamps: Vec<u64> = std::iter::repeat_n(day0, 6).collect();
        let mut daily: BTreeMap<u64, u64> = BTreeMap::new();
        for &ts in &timestamps {
            *daily.entry(ts / 86400).or_insert(0) += 1;
        }
        let daily_avg = 2.0;
        let score = compute_anomaly_score(&daily, daily_avg, &timestamps);
        assert_eq!(
            score, 0.0,
            "exactly 3x should NOT trigger spike rule, got {score}"
        );
    }

    #[test]
    fn quiet_period_rule_triggers_after_7_days_gap() {
        // Two accesses separated by exactly 8 days.
        let t0: u64 = 1_700_000_000;
        let t1 = t0 + 8 * 86400;
        let timestamps = vec![t0, t1];
        let mut daily: BTreeMap<u64, u64> = BTreeMap::new();
        for &ts in &timestamps {
            *daily.entry(ts / 86400).or_insert(0) += 1;
        }
        let daily_avg = 1.0;
        let score = compute_anomaly_score(&daily, daily_avg, &timestamps);
        assert!(
            (score - 0.5).abs() < f64::EPSILON,
            "8-day gap should score 0.5, got {score}"
        );
    }

    #[test]
    fn quiet_period_rule_does_not_trigger_under_7_days() {
        // Two accesses separated by 6 days.
        let t0: u64 = 1_700_000_000;
        let t1 = t0 + 6 * 86400;
        let timestamps = vec![t0, t1];
        let mut daily: BTreeMap<u64, u64> = BTreeMap::new();
        for &ts in &timestamps {
            *daily.entry(ts / 86400).or_insert(0) += 1;
        }
        let daily_avg = 1.0;
        let score = compute_anomaly_score(&daily, daily_avg, &timestamps);
        assert_eq!(
            score, 0.0,
            "6-day gap should NOT trigger quiet rule, got {score}"
        );
    }

    #[test]
    fn both_rules_score_is_max_not_sum() {
        // Spike (0.6) + quiet gap (0.5) → max = 0.6, not 1.1
        let t0: u64 = 1_700_000_000;
        let t1 = t0 + 8 * 86400; // quiet gap triggers (0.5)
                                 // Add a spike on day 0 (7 accesses) with avg=2.0 (0.6)
        let mut timestamps: Vec<u64> = std::iter::repeat_n(t0, 7).collect();
        timestamps.push(t1);
        timestamps.sort_unstable();
        let mut daily: BTreeMap<u64, u64> = BTreeMap::new();
        for &ts in &timestamps {
            *daily.entry(ts / 86400).or_insert(0) += 1;
        }
        let daily_avg = 2.0;
        let score = compute_anomaly_score(&daily, daily_avg, &timestamps);
        assert!(score <= 1.0, "score must not exceed 1.0, got {score}");
        assert!(
            (score - 0.6).abs() < f64::EPSILON,
            "max of 0.6 and 0.5 should be 0.6, got {score}"
        );
    }

    // ── compute_analytics integration ─────────────────────────────────────────

    #[test]
    fn analytics_empty_when_no_log() {
        with_audit_home(|_tmp| {
            let report = compute_analytics(Period::All).unwrap();
            assert!(report.secrets.is_empty());
            assert!(!report.generated_at.is_empty());
        });
    }

    #[test]
    fn analytics_counts_access_correctly() {
        with_audit_home(|tmp| {
            let log_path = tmp.join(".phantom/audit.log");
            let now = now_unix();
            write_synthetic_log(
                &log_path,
                &[
                    (now - 100, "vault.retrieve", Some("KEY_A")),
                    (now - 50, "vault.retrieve", Some("KEY_A")),
                    (now - 10, "vault.store", Some("KEY_B")),
                ],
            );

            let report = compute_analytics(Period::All).unwrap();
            assert_eq!(report.secrets.len(), 2);

            let key_a = report.secrets.iter().find(|s| s.name == "KEY_A").unwrap();
            assert_eq!(key_a.access_count, 2);

            let key_b = report.secrets.iter().find(|s| s.name == "KEY_B").unwrap();
            assert_eq!(key_b.access_count, 1);
        });
    }

    #[test]
    fn analytics_detects_spike_anomaly() {
        with_audit_home(|tmp| {
            let log_path = tmp.join(".phantom/audit.log");
            // Create a day bucket with a huge spike: 50 accesses on one day,
            // 1 access on 4 other days → avg ≈ 54/5 ≈ 10.8, spike = 50 > 3×10.8 = 32.4
            let base_day = 1_700_000_000_u64 / 86400 * 86400;
            let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
            // Spread 1 access/day on days 1-4
            for i in 1_u64..=4 {
                entries.push((base_day + i * 86400, "vault.retrieve", Some("SPIKE_KEY")));
            }
            // 50 accesses on day 0
            for _ in 0..50 {
                entries.push((base_day + 10, "vault.retrieve", Some("SPIKE_KEY")));
            }

            write_synthetic_log(&log_path, &entries);

            let report = compute_analytics(Period::All).unwrap();
            let s = report
                .secrets
                .iter()
                .find(|s| s.name == "SPIKE_KEY")
                .unwrap();
            assert!(
                s.anomaly_score >= 0.6,
                "spike should produce anomaly_score >= 0.6, got {}",
                s.anomaly_score
            );
        });
    }

    #[test]
    fn analytics_detects_quiet_period_anomaly() {
        with_audit_home(|tmp| {
            let log_path = tmp.join(".phantom/audit.log");
            let t0: u64 = 1_700_000_000;
            let t1 = t0 + 10 * 86400; // 10-day gap
            write_synthetic_log(
                &log_path,
                &[
                    (t0, "vault.retrieve", Some("QUIET_KEY")),
                    (t1, "vault.retrieve", Some("QUIET_KEY")),
                ],
            );

            let report = compute_analytics(Period::All).unwrap();
            let s = report
                .secrets
                .iter()
                .find(|s| s.name == "QUIET_KEY")
                .unwrap();
            assert!(
                s.anomaly_score >= 0.5,
                "quiet-period should produce anomaly_score >= 0.5, got {}",
                s.anomaly_score
            );
        });
    }

    #[test]
    fn analytics_max_min_daily_correct() {
        with_audit_home(|tmp| {
            let log_path = tmp.join(".phantom/audit.log");
            let day0 = 1_700_000_000_u64 / 86400 * 86400;
            // day0: 3 accesses, day1: 1 access
            let entries = vec![
                (day0 + 10, "vault.retrieve", Some("K")),
                (day0 + 20, "vault.retrieve", Some("K")),
                (day0 + 30, "vault.retrieve", Some("K")),
                (day0 + 86400 + 10, "vault.retrieve", Some("K")),
            ];
            write_synthetic_log(&log_path, &entries);

            let report = compute_analytics(Period::All).unwrap();
            let s = report.secrets.iter().find(|s| s.name == "K").unwrap();
            assert_eq!(s.max_daily, 3);
            assert_eq!(s.min_daily, 1);
        });
    }

    #[test]
    fn analytics_period_cutoff_filters_old_events() {
        with_audit_home(|tmp| {
            let log_path = tmp.join(".phantom/audit.log");
            let now = now_unix();
            // One very old event (40 days ago) and one recent (1 day ago)
            let entries = vec![
                (
                    now.saturating_sub(40 * 86400),
                    "vault.retrieve",
                    Some("OLD_KEY"),
                ),
                (
                    now.saturating_sub(86400),
                    "vault.retrieve",
                    Some("RECENT_KEY"),
                ),
            ];
            write_synthetic_log(&log_path, &entries);

            let report = compute_analytics(Period::Days7).unwrap();
            assert!(
                report.secrets.iter().all(|s| s.name != "OLD_KEY"),
                "OLD_KEY should be excluded by 7d period filter"
            );
            assert!(
                report.secrets.iter().any(|s| s.name == "RECENT_KEY"),
                "RECENT_KEY should be included"
            );
        });
    }

    // ── export_records ────────────────────────────────────────────────────────

    #[test]
    fn export_records_returns_sorted_by_ts() {
        with_audit_home(|tmp| {
            let log_path = tmp.join(".phantom/audit.log");
            let now = now_unix();
            let entries = vec![
                (now - 200, "vault.retrieve", Some("K")),
                (now - 10, "vault.store", Some("K")),
                (now - 100, "vault.retrieve", Some("K")),
            ];
            write_synthetic_log(&log_path, &entries);

            let records = export_records(Period::All, None).unwrap();
            assert_eq!(records.len(), 3);
            assert!(records[0].ts <= records[1].ts);
            assert!(records[1].ts <= records[2].ts);
        });
    }

    #[test]
    fn export_records_min_anomaly_score_filters() {
        with_audit_home(|tmp| {
            let log_path = tmp.join(".phantom/audit.log");
            // NORMAL_KEY: uniform access, no anomaly
            let now = now_unix();
            let mut entries = Vec::new();
            for i in 0..3_u64 {
                entries.push((now - i * 86400, "vault.retrieve", Some("NORMAL_KEY")));
            }
            // ANOMALY_KEY: gap of 10 days → anomaly_score >= 0.5
            entries.push((now - 11 * 86400, "vault.retrieve", Some("ANOMALY_KEY")));
            entries.push((now - 86400, "vault.retrieve", Some("ANOMALY_KEY")));

            write_synthetic_log(&log_path, &entries);

            let records = export_records(Period::All, Some(0.5)).unwrap();
            // Only ANOMALY_KEY has score >= 0.5
            assert!(
                records.iter().all(|r| r.name == "ANOMALY_KEY"),
                "min_anomaly_score=0.5 should filter to ANOMALY_KEY only; got {:?}",
                records.iter().map(|r| &r.name).collect::<Vec<_>>()
            );
        });
    }

    #[test]
    fn export_records_skips_events_without_name() {
        with_audit_home(|tmp| {
            let log_path = tmp.join(".phantom/audit.log");
            let now = now_unix();
            // One named event and one without a name (cloud.push)
            let entries: Vec<(u64, &str, Option<&str>)> = vec![
                (now - 100, "vault.retrieve", Some("K")),
                (now - 50, "cloud.push", None),
            ];
            write_synthetic_log(&log_path, &entries);

            let records = export_records(Period::All, None).unwrap();
            assert_eq!(records.len(), 1, "nameless events should be excluded");
            assert_eq!(records[0].name, "K");
        });
    }

    // ── CSV ───────────────────────────────────────────────────────────────────

    #[test]
    fn records_to_csv_has_header_and_correct_columns() {
        let records = vec![AccessRecord {
            ts: 1_700_000_000,
            datetime: "2023-11-14T22:13:20Z".to_string(),
            op: "vault.retrieve".to_string(),
            name: "OPENAI_API_KEY".to_string(),
            process: "phantom".to_string(),
        }];
        let csv = records_to_csv(&records);
        assert!(csv.starts_with("ts,datetime,op,name,process\n"));
        assert!(csv.contains("1700000000"));
        assert!(csv.contains("vault.retrieve"));
        assert!(csv.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn records_to_csv_escapes_commas_in_fields() {
        let records = vec![AccessRecord {
            ts: 1_700_000_000,
            datetime: "2023-11-14T22:13:20Z".to_string(),
            op: "vault.retrieve".to_string(),
            name: "KEY,WITH,COMMAS".to_string(),
            process: "phantom".to_string(),
        }];
        let csv = records_to_csv(&records);
        assert!(
            csv.contains("\"KEY,WITH,COMMAS\""),
            "commas should be CSV-escaped"
        );
    }

    #[test]
    fn iso8601_format_known_value() {
        // 2023-11-14 22:13:20 UTC = 1700000000
        let s = unix_to_iso8601(1_700_000_000);
        assert_eq!(s, "2023-11-14T22:13:20Z");
    }
}
