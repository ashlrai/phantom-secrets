//! Structured audit analytics export and compliance report generation.
//!
//! Provides `AuditExporter` which reads `~/.phantom/audit.log` and the
//! `~/.phantom/leak-incidents.jsonl` store, then produces:
//!
//! - **CSV / JSON export** of raw audit events filtered by date range,
//!   secret name, operation type, or user (pid-based proxy).
//! - **Compliance reports** with an access-frequency heatmap, a leak-incident
//!   timeline, a rotation-timing audit, and a 1-page anomaly executive summary.
//! - **Cloud sync** — when `PHANTOM_AUDIT_ENCRYPTION=cloud-signed` the report
//!   is stored under `~/.phantom/reports/` and pushed to phm.dev.
//!
//! ## Export schema
//!
//! Each exported row contains:
//! `timestamp`, `operation`, `secret_name`, `pid`, `hostname`, `severity`.
//!
//! `hostname` is decrypted from `encrypted_context` when available; falls back
//! to `"unknown"`.  `severity` is derived from the operation class:
//!
//! | operation prefix | severity |
//! |-----------------|----------|
//! | `proxy.response_leak` | high |
//! | `proxy.rate_event` | medium |
//! | `vault.delete` | medium |
//! | everything else | low |

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::analytics::unix_to_iso8601;
use crate::leak_correlation::LeakIncident;

// ──────────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────────

/// Severity of a single audit export row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportSeverity {
    High,
    Medium,
    Low,
}

impl ExportSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            ExportSeverity::High => "high",
            ExportSeverity::Medium => "medium",
            ExportSeverity::Low => "low",
        }
    }

    fn from_op(op: &str) -> Self {
        if op == "proxy.response_leak" {
            ExportSeverity::High
        } else if op == "proxy.rate_event" || op == "vault.delete" {
            ExportSeverity::Medium
        } else {
            ExportSeverity::Low
        }
    }
}

/// A single row in a CSV / JSON export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExportRow {
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// ISO-8601 datetime (UTC).
    pub datetime: String,
    /// Operation name (e.g. `vault.retrieve`).
    pub operation: String,
    /// Secret name or empty string for ops without a name.
    pub secret_name: String,
    /// Process ID.
    pub pid: u64,
    /// Hostname (decrypted from `encrypted_context` if available, else `"unknown"`).
    pub hostname: String,
    /// Derived severity for the operation.
    pub severity: ExportSeverity,
}

// ──────────────────────────────────────────────────────────────────────────────
// Compliance report sub-types
// ──────────────────────────────────────────────────────────────────────────────

/// Per-secret access count per calendar day (YYYY-MM-DD).
/// Used for the access-frequency heatmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapEntry {
    /// Secret name.
    pub secret_name: String,
    /// BTreeMap of `YYYY-MM-DD` → access count.
    pub daily_counts: BTreeMap<String, u64>,
    /// Total accesses across the observed period.
    pub total: u64,
}

/// Single entry in the leak-incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakTimelineEntry {
    /// Stable incident identifier.
    pub incident_id: String,
    /// Secret name that leaked.
    pub secret_name: String,
    /// Location where the leak was detected.
    pub location_label: String,
    /// ISO-8601 first-seen timestamp.
    pub first_seen: String,
    /// ISO-8601 last-seen timestamp.
    pub last_seen: String,
    /// Number of contributing events.
    pub occurrences: usize,
    /// Confidence score [0.0, 1.0].
    pub confidence: f64,
}

/// Rotation-timing entry for a single secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationAuditEntry {
    /// Secret name.
    pub secret_name: String,
    /// ISO-8601 datetime of the last `vault.store` event (rotation).
    /// `None` if never stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rotated_at: Option<String>,
    /// Unix timestamp of the last rotation.
    pub last_rotated_ts: u64,
    /// Number of days since the last rotation (or since the first audit event
    /// if no rotation is recorded).
    pub days_since_rotation: u64,
    /// Unix timestamp of the last validation success (`vault.validate` op), 0 if none.
    pub last_validated_ts: u64,
    /// ISO-8601 of last validation, or None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_validated_at: Option<String>,
    /// Days since last validation, or None if never validated.
    pub days_since_validation: Option<u64>,
}

/// Executive summary for high-confidence anomaly incidents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalySummaryEntry {
    /// Secret name.
    pub secret_name: String,
    /// Anomaly score [0.0, 1.0].
    pub anomaly_score: f64,
    /// Human-readable reason.
    pub reason: String,
    /// Number of access events in the observed period.
    pub access_count: u64,
    /// ISO-8601 of the most recent access.
    pub last_access_at: String,
}

/// Full compliance report produced by `AuditExporter::generate_compliance_report`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// ISO-8601 generation timestamp.
    pub generated_at: String,
    /// Date range covered: ISO-8601 start (inclusive).
    pub period_from: String,
    /// Date range covered: ISO-8601 end (inclusive).
    pub period_to: String,
    /// Access-frequency heatmap — one entry per secret with daily buckets.
    pub heatmap: Vec<HeatmapEntry>,
    /// Chronological leak-incident timeline.
    pub leak_timeline: Vec<LeakTimelineEntry>,
    /// Rotation timing audit for every secret that appears in the log.
    pub rotation_audit: Vec<RotationAuditEntry>,
    /// 1-page anomaly executive summary (high-score secrets, sorted desc).
    pub anomaly_summary: Vec<AnomalySummaryEntry>,
    /// Total events in the analysed period.
    pub total_events: u64,
    /// Total distinct secrets seen.
    pub distinct_secrets: usize,
    /// Number of high-severity events (proxy.response_leak).
    pub high_severity_events: u64,
}

// ──────────────────────────────────────────────────────────────────────────────
// Filter parameters
// ──────────────────────────────────────────────────────────────────────────────

/// Filter parameters for `AuditExporter::export_rows`.
#[derive(Debug, Default, Clone)]
pub struct ExportFilter {
    /// Include only events at or after this Unix timestamp (0 = no lower bound).
    pub from_ts: u64,
    /// Include only events at or before this Unix timestamp (0 = no upper bound).
    pub to_ts: u64,
    /// Include only events whose `name` matches this string (exact, case-sensitive).
    pub secret_name: Option<String>,
    /// Include only events whose `op` contains this substring.
    pub operation: Option<String>,
    /// Include only events whose `pid` equals this value.
    pub pid: Option<u64>,
}

impl ExportFilter {
    /// Build a filter from CLI-style date strings (`YYYY-MM-DD` or empty).
    pub fn from_date_strings(from: &str, to: &str) -> Self {
        Self {
            from_ts: parse_date_to_ts(from),
            to_ts: parse_date_to_ts_end(to),
            ..Default::default()
        }
    }

    fn matches(&self, row: &AuditExportRow) -> bool {
        if self.from_ts > 0 && row.timestamp < self.from_ts {
            return false;
        }
        if self.to_ts > 0 && row.timestamp > self.to_ts {
            return false;
        }
        if let Some(ref name) = self.secret_name {
            if row.secret_name != *name {
                return false;
            }
        }
        if let Some(ref op) = self.operation {
            if !row.operation.contains(op.as_str()) {
                return false;
            }
        }
        if let Some(pid) = self.pid {
            if row.pid != pid {
                return false;
            }
        }
        true
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// AuditExporter
// ──────────────────────────────────────────────────────────────────────────────

/// Main entry point for audit analytics export and compliance report generation.
pub struct AuditExporter {
    audit_log_path: PathBuf,
    incidents_path: PathBuf,
    reports_dir: PathBuf,
    hmac_key: Option<Vec<u8>>,
}

impl AuditExporter {
    /// Create a new exporter using paths derived from the current `HOME`.
    pub fn new() -> std::io::Result<Self> {
        let home = home_dir()?;
        let phantom_dir = home.join(".phantom");
        let audit_log_path = phantom_dir.join("audit.log");
        let incidents_path = phantom_dir.join("leak-incidents.jsonl");
        let reports_dir = phantom_dir.join("reports");

        // Load HMAC key for context decryption (best-effort).
        let hmac_key = load_hmac_key(&audit_log_path).ok();

        Ok(Self {
            audit_log_path,
            incidents_path,
            reports_dir,
            hmac_key,
        })
    }

    /// Create an exporter pointing at custom paths (used in tests).
    pub fn with_paths(
        audit_log_path: PathBuf,
        incidents_path: PathBuf,
        reports_dir: PathBuf,
    ) -> Self {
        let hmac_key = load_hmac_key(&audit_log_path).ok();
        Self {
            audit_log_path,
            incidents_path,
            reports_dir,
            hmac_key,
        }
    }

    /// Read audit log and return rows matching `filter`, sorted by timestamp ascending.
    ///
    /// Decrypts `encrypted_context` to populate `hostname` when the HMAC key
    /// is available. Falls back to `"unknown"` otherwise.
    pub fn export_rows(&self, filter: &ExportFilter) -> std::io::Result<Vec<AuditExportRow>> {
        if !self.audit_log_path.exists() {
            return Ok(vec![]);
        }

        let file = std::fs::File::open(&self.audit_log_path)?;
        let reader = std::io::BufReader::new(file);
        let mut rows: Vec<AuditExportRow> = Vec::new();

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Skip chain-marker lines.
            if v.get("hmac_chain_started_at").is_some() {
                continue;
            }
            let op = match v.get("op").and_then(|o| o.as_str()) {
                Some(op) => op.to_string(),
                None => continue,
            };
            let ts = v.get("ts").and_then(|t| t.as_u64()).unwrap_or(0);
            let pid = v.get("pid").and_then(|p| p.as_u64()).unwrap_or(0);
            let secret_name = v
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();

            // Attempt hostname decryption from encrypted_context.
            let hostname = self.extract_hostname(&v);
            let severity = ExportSeverity::from_op(&op);

            let row = AuditExportRow {
                timestamp: ts,
                datetime: unix_to_iso8601(ts),
                operation: op,
                secret_name,
                pid,
                hostname,
                severity,
            };

            if filter.matches(&row) {
                rows.push(row);
            }
        }

        rows.sort_by_key(|r| r.timestamp);
        Ok(rows)
    }

    /// Render `rows` as RFC 4180 CSV with header.
    pub fn rows_to_csv(rows: &[AuditExportRow]) -> String {
        let mut out = String::from("timestamp,datetime,operation,secret_name,pid,hostname,severity\n");
        for r in rows {
            let datetime = csv_escape(&r.datetime);
            let operation = csv_escape(&r.operation);
            let secret_name = csv_escape(&r.secret_name);
            let hostname = csv_escape(&r.hostname);
            out.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                r.timestamp,
                datetime,
                operation,
                secret_name,
                r.pid,
                hostname,
                r.severity.as_str()
            ));
        }
        out
    }

    /// Render `rows` as a JSON array string (pretty-printed).
    pub fn rows_to_json(rows: &[AuditExportRow]) -> std::io::Result<String> {
        serde_json::to_string_pretty(rows)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Generate a full compliance report for events in `[from_ts, to_ts]`.
    ///
    /// Pass `from_ts = 0` for no lower bound; `to_ts = 0` for no upper bound.
    pub fn generate_compliance_report(
        &self,
        from_ts: u64,
        to_ts: u64,
    ) -> std::io::Result<ComplianceReport> {
        let filter = ExportFilter {
            from_ts,
            to_ts,
            ..Default::default()
        };
        let rows = self.export_rows(&filter)?;
        let now_ts = now_unix();

        // ── 1. Access-frequency heatmap ──────────────────────────────────────
        let heatmap = self.build_heatmap(&rows);

        // ── 2. Leak incident timeline ────────────────────────────────────────
        let leak_timeline = self.build_leak_timeline(from_ts, to_ts)?;

        // ── 3. Rotation timing audit ─────────────────────────────────────────
        let rotation_audit = self.build_rotation_audit(&rows, now_ts);

        // ── 4. Anomaly executive summary ─────────────────────────────────────
        let anomaly_summary = self.build_anomaly_summary(&rows);

        // ── Metadata ─────────────────────────────────────────────────────────
        let total_events = rows.len() as u64;
        let high_severity_events = rows
            .iter()
            .filter(|r| r.severity == ExportSeverity::High)
            .count() as u64;
        let distinct_secrets: std::collections::HashSet<&str> = rows
            .iter()
            .filter(|r| !r.secret_name.is_empty())
            .map(|r| r.secret_name.as_str())
            .collect();

        let effective_from = if from_ts > 0 {
            unix_to_iso8601(from_ts)
        } else {
            rows.first()
                .map(|r| unix_to_iso8601(r.timestamp))
                .unwrap_or_else(|| unix_to_iso8601(0))
        };
        let effective_to = if to_ts > 0 {
            unix_to_iso8601(to_ts)
        } else {
            unix_to_iso8601(now_ts)
        };

        Ok(ComplianceReport {
            generated_at: unix_to_iso8601(now_ts),
            period_from: effective_from,
            period_to: effective_to,
            heatmap,
            leak_timeline,
            rotation_audit,
            anomaly_summary,
            total_events,
            distinct_secrets: distinct_secrets.len(),
            high_severity_events,
        })
    }

    /// Store a compliance report under `~/.phantom/reports/report-<ts>.json`
    /// and optionally push it to phm.dev when CloudSigned mode is active.
    ///
    /// Returns the path the report was saved to.
    pub fn save_report(&self, report: &ComplianceReport) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(&self.reports_dir)?;

        let ts = now_unix();
        let filename = format!("report-{}.json", ts);
        let path = self.reports_dir.join(&filename);

        let json = serde_json::to_string_pretty(report)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json.as_bytes())?;

        // Cloud push when CloudSigned mode is active.
        if crate::audit::AuditEventEncryption::from_env()
            == crate::audit::AuditEventEncryption::CloudSigned
        {
            // Best-effort, non-blocking.
            let json_clone = json.clone();
            std::thread::spawn(move || {
                let _ = push_report_to_cloud(&json_clone);
            });
        }

        Ok(path)
    }

    /// List all saved reports under `~/.phantom/reports/`.
    pub fn list_reports(&self) -> std::io::Result<Vec<PathBuf>> {
        if !self.reports_dir.exists() {
            return Ok(vec![]);
        }
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&self.reports_dir)?
            .filter_map(|entry| entry.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().map_or(false, |ext| ext == "json")
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map_or(false, |n| n.starts_with("report-"))
            })
            .collect();
        paths.sort();
        Ok(paths)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Attempt to decrypt `encrypted_context` for a log line and extract hostname.
    fn extract_hostname(&self, v: &serde_json::Value) -> String {
        if let Some(key) = &self.hmac_key {
            if let Some(ec) = v.get("encrypted_context").and_then(|e| e.as_str()) {
                if let Ok(ctx) = crate::audit::decrypt_context(ec, key) {
                    return ctx.hostname;
                }
            }
        }
        "unknown".to_string()
    }

    fn build_heatmap(&self, rows: &[AuditExportRow]) -> Vec<HeatmapEntry> {
        // name → day → count
        let mut map: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for row in rows {
            if row.secret_name.is_empty() {
                continue;
            }
            let day = &row.datetime[..10]; // YYYY-MM-DD
            *map.entry(row.secret_name.clone())
                .or_default()
                .entry(day.to_string())
                .or_insert(0) += 1;
        }
        map.into_iter()
            .map(|(secret_name, daily_counts)| {
                let total: u64 = daily_counts.values().sum();
                HeatmapEntry {
                    secret_name,
                    daily_counts,
                    total,
                }
            })
            .collect()
    }

    fn build_leak_timeline(
        &self,
        from_ts: u64,
        to_ts: u64,
    ) -> std::io::Result<Vec<LeakTimelineEntry>> {
        if !self.incidents_path.exists() {
            return Ok(vec![]);
        }

        let incidents = load_all_incidents(&self.incidents_path)?;
        let entries: Vec<LeakTimelineEntry> = incidents
            .into_iter()
            .filter(|inc| {
                if from_ts > 0 && inc.first_seen_ts < from_ts {
                    return false;
                }
                if to_ts > 0 && inc.first_seen_ts > to_ts {
                    return false;
                }
                true
            })
            .map(|inc| LeakTimelineEntry {
                incident_id: inc.incident_id,
                secret_name: inc.secret_name,
                location_label: inc.location_label,
                first_seen: unix_to_iso8601(inc.first_seen_ts),
                last_seen: unix_to_iso8601(inc.last_seen_ts),
                occurrences: inc.event_count,
                confidence: inc.confidence,
            })
            .collect();

        Ok(entries)
    }

    fn build_rotation_audit(
        &self,
        rows: &[AuditExportRow],
        now_ts: u64,
    ) -> Vec<RotationAuditEntry> {
        // last vault.store ts per secret name
        let mut last_store: BTreeMap<String, u64> = BTreeMap::new();
        // last vault.validate ts per secret name
        let mut last_validate: BTreeMap<String, u64> = BTreeMap::new();
        // first seen ts per secret name (fallback)
        let mut first_seen: BTreeMap<String, u64> = BTreeMap::new();

        for row in rows {
            if row.secret_name.is_empty() {
                continue;
            }
            let e = first_seen.entry(row.secret_name.clone()).or_insert(row.timestamp);
            if row.timestamp < *e {
                *e = row.timestamp;
            }
            if row.operation == "vault.store" {
                let e = last_store.entry(row.secret_name.clone()).or_insert(0);
                if row.timestamp > *e {
                    *e = row.timestamp;
                }
            }
            if row.operation == "vault.validate" || row.operation.starts_with("validation.") {
                let e = last_validate.entry(row.secret_name.clone()).or_insert(0);
                if row.timestamp > *e {
                    *e = row.timestamp;
                }
            }
        }

        // Collect all secret names.
        let all_names: std::collections::BTreeSet<String> = rows
            .iter()
            .filter(|r| !r.secret_name.is_empty())
            .map(|r| r.secret_name.clone())
            .collect();

        all_names
            .into_iter()
            .map(|name| {
                let last_rotated_ts = last_store.get(&name).copied().unwrap_or(0);
                let baseline_ts = if last_rotated_ts > 0 {
                    last_rotated_ts
                } else {
                    first_seen.get(&name).copied().unwrap_or(now_ts)
                };
                let days_since_rotation =
                    now_ts.saturating_sub(baseline_ts) / 86400;

                let last_validated_ts = last_validate.get(&name).copied().unwrap_or(0);
                let (days_since_validation, last_validated_at) = if last_validated_ts > 0 {
                    (
                        Some(now_ts.saturating_sub(last_validated_ts) / 86400),
                        Some(unix_to_iso8601(last_validated_ts)),
                    )
                } else {
                    (None, None)
                };

                RotationAuditEntry {
                    last_rotated_at: if last_rotated_ts > 0 {
                        Some(unix_to_iso8601(last_rotated_ts))
                    } else {
                        None
                    },
                    last_rotated_ts,
                    days_since_rotation,
                    last_validated_ts,
                    last_validated_at,
                    days_since_validation,
                    secret_name: name,
                }
            })
            .collect()
    }

    fn build_anomaly_summary(&self, rows: &[AuditExportRow]) -> Vec<AnomalySummaryEntry> {
        use std::collections::HashMap;

        // Group timestamps by name.
        let mut by_name: HashMap<String, Vec<u64>> = HashMap::new();
        for row in rows {
            if row.secret_name.is_empty() {
                continue;
            }
            by_name
                .entry(row.secret_name.clone())
                .or_default()
                .push(row.timestamp);
        }

        let mut entries: Vec<AnomalySummaryEntry> = by_name
            .into_iter()
            .filter_map(|(name, mut timestamps)| {
                if timestamps.is_empty() {
                    return None;
                }
                timestamps.sort_unstable();

                let access_count = timestamps.len() as u64;
                let last_ts = *timestamps.last().unwrap();

                // Compute simple anomaly score using the same rules as analytics.rs
                // Rule 1: spike — any day > 3× daily_avg
                let mut daily: BTreeMap<u64, u64> = BTreeMap::new();
                for &ts in &timestamps {
                    *daily.entry(ts / 86400).or_insert(0) += 1;
                }
                let first_ts = *timestamps.first().unwrap();
                let span_days = if last_ts > first_ts {
                    ((last_ts - first_ts) as f64 / 86400.0).ceil().max(1.0)
                } else {
                    1.0
                };
                let daily_avg = access_count as f64 / span_days;

                let mut score: f64 = 0.0;
                let mut reasons: Vec<String> = Vec::new();

                if daily_avg > 0.0 {
                    for &count in daily.values() {
                        if count as f64 > 3.0 * daily_avg {
                            score = score.max(0.6);
                            reasons.push(format!(
                                "daily spike: {count} accesses (avg {daily_avg:.1})"
                            ));
                            break;
                        }
                    }
                }
                // Rule 2: quiet gap ≥ 7 days
                if timestamps.len() >= 2 {
                    for w in timestamps.windows(2) {
                        if w[1].saturating_sub(w[0]) >= 7 * 86400 {
                            score = score.max(0.5);
                            reasons.push("re-access after ≥7 quiet days".to_string());
                            break;
                        }
                    }
                }

                // Only include secrets that have a non-zero anomaly score.
                if score == 0.0 {
                    return None;
                }

                Some(AnomalySummaryEntry {
                    secret_name: name,
                    anomaly_score: score,
                    reason: reasons.join("; "),
                    access_count,
                    last_access_at: unix_to_iso8601(last_ts),
                })
            })
            .collect();

        // Sort by anomaly score descending.
        entries.sort_by(|a, b| {
            b.anomaly_score
                .partial_cmp(&a.anomaly_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.secret_name.cmp(&b.secret_name))
        });
        entries
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Cloud push (best-effort)
// ──────────────────────────────────────────────────────────────────────────────

fn push_report_to_cloud(json: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let resp = client
        .post("https://phm.dev/api/reports/ingest")
        .header("Content-Type", "application/json")
        .header("X-Phantom-Version", env!("CARGO_PKG_VERSION"))
        .body(json.to_string())
        .send()?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()).into())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

fn load_all_incidents(path: &Path) -> std::io::Result<Vec<LeakIncident>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut incidents = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(inc) = serde_json::from_str::<LeakIncident>(trimmed) {
            incidents.push(inc);
        }
    }
    Ok(incidents)
}

fn load_hmac_key(audit_log_path: &Path) -> std::io::Result<Vec<u8>> {
    let key_path = audit_log_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("audit-hmac-key");
    if !key_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HMAC key not found",
        ));
    }
    let hex_str = std::fs::read_to_string(&key_path)?;
    hex::decode(hex_str.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

fn home_dir() -> std::io::Result<PathBuf> {
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "cannot resolve home directory",
    ))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Parse `YYYY-MM-DD` into a Unix timestamp at midnight UTC.
/// Returns 0 on parse failure or empty string.
pub fn parse_date_to_ts(s: &str) -> u64 {
    if s.is_empty() {
        return 0;
    }
    parse_date_inner(s).unwrap_or(0)
}

/// Parse `YYYY-MM-DD` into a Unix timestamp at 23:59:59 UTC (end of day).
/// Returns 0 on parse failure or empty string.
pub fn parse_date_to_ts_end(s: &str) -> u64 {
    if s.is_empty() {
        return 0;
    }
    parse_date_inner(s)
        .map(|ts| ts + 86399)
        .unwrap_or(0)
}

fn parse_date_inner(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.splitn(3, '-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    let day: i64 = parts[2].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Algorithm: http://howardhinnant.github.io/date_algorithms.html (ymd_to_days)
    let y = if month <= 2 { year - 1 } else { year };
    let m = month as i64;
    let d = day as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86400)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_exporter(tmp: &std::path::Path) -> AuditExporter {
        AuditExporter::with_paths(
            tmp.join(".phantom/audit.log"),
            tmp.join(".phantom/leak-incidents.jsonl"),
            tmp.join(".phantom/reports"),
        )
    }

    fn write_audit_log(path: &std::path::Path, entries: &[(u64, &str, Option<&str>)]) {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        for (ts, op, name) in entries {
            let line = if let Some(n) = name {
                format!(
                    r#"{{"ts":{ts},"op":"{op}","name":"{n}","pid":42,"process":"phantom"}}"#
                )
            } else {
                format!(r#"{{"ts":{ts},"op":"{op}","pid":42,"process":"phantom"}}"#)
            };
            writeln!(f, "{}", line).unwrap();
        }
    }

    fn write_incident(path: &std::path::Path, inc: &LeakIncident) {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let line = serde_json::to_string(inc).unwrap();
        writeln!(f, "{}", line).unwrap();
    }

    // ── Test 1: basic export returns rows sorted by timestamp ─────────────────

    #[test]
    fn export_rows_sorted_by_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());
        let now = 1_750_000_000_u64;

        write_audit_log(
            &ex.audit_log_path,
            &[
                (now - 200, "vault.retrieve", Some("KEY_A")),
                (now - 10, "vault.store", Some("KEY_A")),
                (now - 100, "vault.retrieve", Some("KEY_B")),
            ],
        );

        let rows = ex.export_rows(&ExportFilter::default()).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows[0].timestamp <= rows[1].timestamp);
        assert!(rows[1].timestamp <= rows[2].timestamp);
    }

    // ── Test 2: filter by secret name ─────────────────────────────────────────

    #[test]
    fn export_rows_filter_by_secret_name() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());
        let now = 1_750_000_000_u64;

        write_audit_log(
            &ex.audit_log_path,
            &[
                (now - 200, "vault.retrieve", Some("KEY_A")),
                (now - 100, "vault.retrieve", Some("KEY_B")),
            ],
        );

        let filter = ExportFilter {
            secret_name: Some("KEY_A".to_string()),
            ..Default::default()
        };
        let rows = ex.export_rows(&filter).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].secret_name, "KEY_A");
    }

    // ── Test 3: filter by date range (from_ts / to_ts) ────────────────────────

    #[test]
    fn export_rows_filter_by_date_range() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());
        let base = 1_750_000_000_u64;

        write_audit_log(
            &ex.audit_log_path,
            &[
                (base - 3 * 86400, "vault.retrieve", Some("OLD_KEY")),
                (base, "vault.retrieve", Some("NEW_KEY")),
            ],
        );

        let filter = ExportFilter {
            from_ts: base - 86400, // 1 day before base
            ..Default::default()
        };
        let rows = ex.export_rows(&filter).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].secret_name, "NEW_KEY");
    }

    // ── Test 4: filter by operation ───────────────────────────────────────────

    #[test]
    fn export_rows_filter_by_operation() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());
        let now = 1_750_000_000_u64;

        write_audit_log(
            &ex.audit_log_path,
            &[
                (now - 100, "vault.retrieve", Some("KEY")),
                (now - 50, "vault.store", Some("KEY")),
                (now - 10, "cloud.push", None),
            ],
        );

        let filter = ExportFilter {
            operation: Some("vault.store".to_string()),
            ..Default::default()
        };
        let rows = ex.export_rows(&filter).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].operation, "vault.store");
    }

    // ── Test 5: CSV format has correct header and escaping ────────────────────

    #[test]
    fn rows_to_csv_correct_header_and_escape() {
        let rows = vec![AuditExportRow {
            timestamp: 1_750_000_000,
            datetime: "2025-06-15T06:13:20Z".to_string(),
            operation: "vault.retrieve".to_string(),
            secret_name: "KEY,WITH,COMMAS".to_string(),
            pid: 42,
            hostname: "myhost".to_string(),
            severity: ExportSeverity::Low,
        }];

        let csv = AuditExporter::rows_to_csv(&rows);
        assert!(csv.starts_with(
            "timestamp,datetime,operation,secret_name,pid,hostname,severity\n"
        ));
        assert!(csv.contains("\"KEY,WITH,COMMAS\""), "commas should be CSV-escaped");
        assert!(csv.contains("low"));
        assert!(csv.contains("myhost"));
    }

    // ── Test 6: compliance report heatmap correctness ─────────────────────────

    #[test]
    fn compliance_report_heatmap_counts_correctly() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());
        // Day 0 = 1_728_000_000 / 86400 * 86400 for a round day
        let day0 = 1_728_000_000_u64 / 86400 * 86400;

        write_audit_log(
            &ex.audit_log_path,
            &[
                (day0 + 100, "vault.retrieve", Some("API_KEY")),
                (day0 + 200, "vault.retrieve", Some("API_KEY")),
                (day0 + 86400 + 100, "vault.retrieve", Some("API_KEY")),
                (day0 + 100, "vault.retrieve", Some("OTHER_KEY")),
            ],
        );

        let report = ex.generate_compliance_report(0, 0).unwrap();
        let api_entry = report
            .heatmap
            .iter()
            .find(|h| h.secret_name == "API_KEY")
            .unwrap();
        assert_eq!(api_entry.total, 3);
        // day0 bucket should have count 2
        let day0_str = &unix_to_iso8601(day0)[..10];
        assert_eq!(api_entry.daily_counts.get(day0_str).copied().unwrap_or(0), 2);
    }

    // ── Test 7: compliance report leak timeline includes incidents ────────────

    #[test]
    fn compliance_report_leak_timeline_from_incidents() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());
        let now = 1_750_000_000_u64;

        let inc = LeakIncident {
            incident_id: "test-id".to_string(),
            secret_name: "STRIPE_KEY".to_string(),
            location_label: "body".to_string(),
            first_seen_ts: now - 3600,
            last_seen_ts: now - 1800,
            event_count: 4,
            confidence: 0.95,
            remediation: "rotate".to_string(),
        };
        write_incident(&ex.incidents_path, &inc);
        // Also write a dummy log entry so the report has something.
        write_audit_log(
            &ex.audit_log_path,
            &[(now - 3600, "proxy.response_leak", Some("STRIPE_KEY"))],
        );

        let report = ex.generate_compliance_report(0, 0).unwrap();
        assert_eq!(report.leak_timeline.len(), 1);
        assert_eq!(report.leak_timeline[0].secret_name, "STRIPE_KEY");
        assert_eq!(report.leak_timeline[0].occurrences, 4);
        assert!((report.leak_timeline[0].confidence - 0.95).abs() < 1e-9);
    }

    // ── Test 8: compliance report rotation audit identifies unrotated secrets ─

    #[test]
    fn compliance_report_rotation_audit_identifies_unrotated() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());
        // Use actual now_unix() so days_since_rotation is computed correctly
        // relative to the report's internal now_unix() call.
        let now = now_unix();

        // KEY_A was stored 90 days ago; KEY_B only retrieved, never stored.
        write_audit_log(
            &ex.audit_log_path,
            &[
                (now - 90 * 86400, "vault.store", Some("KEY_A")),
                (now - 86400, "vault.retrieve", Some("KEY_A")),
                (now - 86400, "vault.retrieve", Some("KEY_B")),
            ],
        );

        let report = ex.generate_compliance_report(0, 0).unwrap();
        let key_a = report
            .rotation_audit
            .iter()
            .find(|r| r.secret_name == "KEY_A")
            .unwrap();
        // Allow ±1 day tolerance for clock skew during test execution.
        assert!(
            key_a.days_since_rotation >= 89 && key_a.days_since_rotation <= 91,
            "expected ~90 days, got {}",
            key_a.days_since_rotation
        );
        assert!(key_a.last_rotated_at.is_some());

        let key_b = report
            .rotation_audit
            .iter()
            .find(|r| r.secret_name == "KEY_B")
            .unwrap();
        assert!(key_b.last_rotated_at.is_none());
    }

    // ── Test 9: anomaly summary detects spike ─────────────────────────────────

    #[test]
    fn compliance_report_anomaly_summary_detects_spike() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());
        let day0 = 1_728_000_000_u64 / 86400 * 86400;

        // Create a spike: 1 access/day on days 1-4, then 50 accesses on day 5.
        // avg ≈ (4 + 50) / 5 = 10.8, spike day = 50 > 3×10.8 = 32.4 → triggers.
        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        for i in 1_u64..=4 {
            entries.push((day0 + i * 86400, "vault.retrieve", Some("SPIKE_KEY")));
        }
        for j in 0_u64..50 {
            entries.push((day0 + 5 * 86400 + j, "vault.retrieve", Some("SPIKE_KEY")));
        }
        write_audit_log(&ex.audit_log_path, &entries);

        let report = ex.generate_compliance_report(0, 0).unwrap();
        let entry = report
            .anomaly_summary
            .iter()
            .find(|a| a.secret_name == "SPIKE_KEY")
            .unwrap();
        assert!(
            entry.anomaly_score >= 0.6,
            "spike should produce score >= 0.6, got {}",
            entry.anomaly_score
        );
    }

    // ── Test 10: parse_date_to_ts round-trip ──────────────────────────────────

    #[test]
    fn parse_date_to_ts_known_value() {
        // 2023-11-14 midnight UTC = 1699920000
        let ts = parse_date_to_ts("2023-11-14");
        // 1700000000 is 2023-11-14T22:13:20Z, so midnight = 1699920000
        assert_eq!(ts, 1_699_920_000, "2023-11-14 midnight UTC");
    }

    #[test]
    fn parse_date_to_ts_end_is_end_of_day() {
        let ts_start = parse_date_to_ts("2023-11-14");
        let ts_end = parse_date_to_ts_end("2023-11-14");
        assert_eq!(ts_end - ts_start, 86399, "end-of-day should be 86399s after start");
    }

    #[test]
    fn parse_date_empty_returns_zero() {
        assert_eq!(parse_date_to_ts(""), 0);
        assert_eq!(parse_date_to_ts_end(""), 0);
    }

    // ── Test 11: save_report creates file ────────────────────────────────────

    #[test]
    fn save_report_creates_file_in_reports_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());

        // Minimal report
        write_audit_log(
            &ex.audit_log_path,
            &[(1_750_000_000, "vault.retrieve", Some("KEY"))],
        );
        let report = ex.generate_compliance_report(0, 0).unwrap();
        let path = ex.save_report(&report).unwrap();

        assert!(path.exists(), "report file should exist");
        assert!(path.extension().map_or(false, |e| e == "json"));

        let listed = ex.list_reports().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], path);
    }

    // ── Test 12: severity classification ─────────────────────────────────────

    #[test]
    fn severity_from_op_correct() {
        assert_eq!(
            ExportSeverity::from_op("proxy.response_leak"),
            ExportSeverity::High
        );
        assert_eq!(
            ExportSeverity::from_op("proxy.rate_event"),
            ExportSeverity::Medium
        );
        assert_eq!(
            ExportSeverity::from_op("vault.delete"),
            ExportSeverity::Medium
        );
        assert_eq!(
            ExportSeverity::from_op("vault.retrieve"),
            ExportSeverity::Low
        );
        assert_eq!(ExportSeverity::from_op("cloud.push"), ExportSeverity::Low);
    }

    // ── Test 13: export rows empty when no log ────────────────────────────────

    #[test]
    fn export_rows_empty_when_no_log() {
        let tmp = tempfile::tempdir().unwrap();
        let ex = make_exporter(tmp.path());
        let rows = ex.export_rows(&ExportFilter::default()).unwrap();
        assert!(rows.is_empty());
    }

    // ── Test 14: filter by pid ────────────────────────────────────────────────

    #[test]
    fn export_rows_filter_by_pid() {
        let tmp = tempfile::tempdir().unwrap();
        // Write log with explicit pid values in JSON
        let log_path = tmp.path().join(".phantom/audit.log");
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            writeln!(
                f,
                r#"{{"ts":1750000000,"op":"vault.retrieve","name":"K1","pid":100,"process":"ph"}}"#
            )
            .unwrap();
            writeln!(
                f,
                r#"{{"ts":1750000001,"op":"vault.retrieve","name":"K2","pid":200,"process":"ph"}}"#
            )
            .unwrap();
        }

        let ex = AuditExporter::with_paths(
            log_path,
            tmp.path().join(".phantom/leak-incidents.jsonl"),
            tmp.path().join(".phantom/reports"),
        );

        let filter = ExportFilter {
            pid: Some(100),
            ..Default::default()
        };
        let rows = ex.export_rows(&filter).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].secret_name, "K1");
        assert_eq!(rows[0].pid, 100);
    }
}
