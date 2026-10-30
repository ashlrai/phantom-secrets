//! `phantom audit` subcommands for reading the JSONL audit log.
//!
//! Actions:
//!   phantom audit show       [--last N] [--op OP] [--name NAME] [--json]
//!   phantom audit tail       [--op OP] [--name NAME]
//!   phantom audit path
//!   phantom audit verify
//!   phantom audit stats      [--json] [--top N] [--analytics] [--min-anomaly-score F]
//!   phantom audit export     [--format csv|json] [--period 7d|30d] [--min-anomaly-score F]
//!   phantom audit analytics  [--window DAYS] [--min-anomaly-score F] [--format json|csv]
//!                            [--export FILE] [--auto-alert-on-anomaly]

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, IsTerminal, Seek, SeekFrom, Write};
use std::path::PathBuf;

mod alerts;
mod analytics;
mod log;
mod report;
mod verify;

pub use alerts::{run_alerts, run_anomalies, run_incidents};
pub use analytics::{run_analytics, run_export, run_stats};
pub use log::{run_path, run_show, run_tail};
pub use report::{run_export_range, run_report};
pub use verify::run_verify;

// ──────────────────────────────────────────────────────────────────────────────
// Subcommand definition (re-exported so main.rs can use it)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum AuditAction {
    /// Project stdin audit NDJSON into schema-versioned, value-free workbench events.
    /// Malformed, oversized (>64 KiB), and unterminated records are discarded.
    Feed,
    /// Print recent audit events (default: last 50)
    Show {
        /// Limit output to the last N events (default 50)
        #[arg(long, default_value_t = 50)]
        last: usize,
        /// Filter by operation (e.g. vault.store, vault.retrieve)
        #[arg(long)]
        op: Option<String>,
        /// Filter by secret name (e.g. OPENAI_API_KEY)
        #[arg(long)]
        name: Option<String>,
        /// Emit raw JSONL instead of pretty-printing
        #[arg(long)]
        json: bool,
        /// Only show response-leak events (op=proxy.response_leak); high-severity
        /// incidents where a real secret escaped an upstream API response.
        #[arg(long)]
        leaked_secrets: bool,
        /// Write the events to this new file (never overwritten) and print
        /// only a one-line summary.
        #[arg(long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
    },
    /// Follow the audit log (like tail -f)
    Tail {
        /// Filter by operation
        #[arg(long)]
        op: Option<String>,
        /// Filter by secret name
        #[arg(long)]
        name: Option<String>,
    },
    /// Print the absolute path to the audit log
    Path,
    /// Verify the HMAC chain integrity of the audit log
    Verify {
        /// Decrypt and display the encrypted_context field for each event (forensics mode)
        #[arg(long)]
        with_context: bool,
    },
    /// Show per-secret access counts and timing from the audit log
    Stats {
        /// Emit raw JSON instead of the human-readable table
        #[arg(long)]
        json: bool,
        /// Only show the top N secrets by access count (0 = all)
        #[arg(long, default_value_t = 0)]
        top: usize,
        /// Include anomaly detection scores in the output (implies --json adds extra fields)
        #[arg(long)]
        analytics: bool,
        /// Only show secrets whose anomaly score is at or above this threshold (0.0–1.0; clamped)
        #[arg(long, value_name = "SCORE", value_parser = parse_score_threshold)]
        min_anomaly_score: Option<f64>,
    },
    /// Export timestamped access records for compliance reports
    Export {
        /// Output format: csv or json
        #[arg(long, default_value = "json")]
        format: String,
        /// Time period: 7d, 30d, or all
        #[arg(long, default_value = "30d")]
        period: String,
        /// Only export records for secrets whose anomaly score is at or above this threshold (0.0–1.0; clamped)
        #[arg(long, value_name = "SCORE", value_parser = parse_score_threshold)]
        min_anomaly_score: Option<f64>,
    },
    /// Export full audit analytics for external dashboards (Datadog, Grafana, CloudWatch)
    Analytics {
        /// Time window in days: exactly the last N days (default: 30; 0 = all history)
        #[arg(long, default_value_t = 30)]
        window: u32,
        /// Only include secrets with anomaly score at or above this threshold (0.0–1.0; clamped)
        #[arg(long, value_name = "SCORE", value_parser = parse_score_threshold)]
        min_anomaly_score: Option<f64>,
        /// Output format: json (default) or csv
        #[arg(long, default_value = "json")]
        format: String,
        /// Create one new file in the current project (never overwrites)
        #[arg(long, value_name = "FILE")]
        export: Option<String>,
        /// Exit with non-zero status if any secret exceeds the anomaly threshold (CI gate)
        #[arg(long)]
        auto_alert_on_anomaly: bool,
    },
    /// Stream real-time anomaly alerts by tailing the audit log
    Anomalies {
        /// Tail the audit log and emit alerts as new events are written (Ctrl-C to stop)
        #[arg(long)]
        realtime: bool,
        /// Minimum anomaly score (0.0–1.0; clamped) at which an alert is emitted (default: 0.5)
        #[arg(long, default_value_t = 0.5, value_name = "SCORE", value_parser = parse_score_threshold)]
        threshold: f64,
        /// Only check this specific secret (omit to check all secrets)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Maximum allowed accesses per hour before triggering a rate-spike alert
        #[arg(long, value_name = "N")]
        max_accesses_per_hour: Option<u64>,
        /// Number of consecutive quiet days before a re-access triggers an alert
        #[arg(long, value_name = "DAYS")]
        max_quiet_days: Option<u64>,
        /// Emit output as JSON lines instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Show correlated leak incidents derived from proxy.response_leak audit events
    ///
    /// Incidents are grouped by (secret, location) within 24-hour windows.
    /// High-confidence incidents (≥ 0.95) indicate the same secret leaked more
    /// than 3 times within an hour - immediate rotation is advised.
    ///
    /// Examples:
    ///   phantom audit incidents
    ///   phantom audit incidents --min-confidence 0.5
    ///   phantom audit incidents --json
    #[command(verbatim_doc_comment)]
    Incidents {
        /// Only show incidents with confidence ≥ this value (default: 0.5)
        #[arg(long, default_value_t = 0.5, value_name = "SCORE", value_parser = parse_min_confidence)]
        min_confidence: f64,
        /// Emit raw JSON lines instead of human-readable output
        #[arg(long)]
        json: bool,
        /// Deprecated and disabled. Incident detection cannot prove or perform
        /// provider credential rotation. Rotate at the provider and store the
        /// replacement from a trusted terminal.
        #[arg(long, hide = true)]
        auto_rotate_on_high: bool,
    },

    /// Export raw audit log rows filtered by date range, secret, or operation
    ///
    /// Examples:
    ///   phantom audit export-range --format csv --from 2026-01-01 --to 2026-06-29 > audit.csv
    ///   phantom audit export-range --format json --name OPENAI_API_KEY
    #[command(verbatim_doc_comment)]
    ExportRange {
        /// Output format: csv or json (default: json)
        #[arg(long, default_value = "json")]
        format: String,
        /// Start date inclusive (YYYY-MM-DD). Omit for no lower bound.
        #[arg(long, value_name = "DATE", default_value = "")]
        from: String,
        /// End date inclusive (YYYY-MM-DD). Omit for no upper bound.
        #[arg(long, value_name = "DATE", default_value = "")]
        to: String,
        /// Filter to a specific secret name (exact match).
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Filter to operations containing this string (e.g. vault.retrieve).
        #[arg(long, value_name = "OP")]
        op: Option<String>,
        /// Filter to events from this PID only.
        #[arg(long, value_name = "PID")]
        pid: Option<u64>,
    },

    /// Show persisted leak-incident alert records from ~/.phantom/leak-alerts.jsonl
    ///
    /// Alerts are emitted at most once per incident per 1-hour window. Use
    /// `--backfill` to re-run the correlation engine and emit any pending alerts
    /// for incidents that have not yet been notified.
    ///
    /// Examples:
    ///   phantom audit alerts
    ///   phantom audit alerts --last 20
    ///   phantom audit alerts --json
    ///   phantom audit alerts --backfill
    #[command(verbatim_doc_comment)]
    Alerts {
        /// Maximum number of recent alerts to return (default: 50)
        #[arg(long, default_value_t = 50)]
        last: usize,
        /// Re-run leak correlation and emit any pending alerts before listing
        #[arg(long)]
        backfill: bool,
        /// Emit raw JSON lines instead of human-readable output
        #[arg(long)]
        json: bool,
    },

    /// Generate a structured compliance report and save to ~/.phantom/reports/
    ///
    /// The report includes:
    ///   - Access-frequency heatmap per secret per day
    ///   - Leak incident timeline
    ///   - Rotation timing audit
    ///   - 1-page anomaly executive summary
    ///
    /// Examples:
    ///   phantom audit report
    ///   phantom audit report --from 2026-01-01 --to 2026-06-29 --save
    #[command(verbatim_doc_comment)]
    Report {
        /// Report type: compliance (default)
        #[arg(long, default_value = "compliance", value_name = "TYPE")]
        r#type: String,
        /// Start date inclusive (YYYY-MM-DD). Omit for full history.
        #[arg(long, value_name = "DATE", default_value = "")]
        from: String,
        /// End date inclusive (YYYY-MM-DD). Omit for no upper bound.
        #[arg(long, value_name = "DATE", default_value = "")]
        to: String,
        /// Save the report to ~/.phantom/reports/ in addition to printing it.
        #[arg(long)]
        save: bool,
        /// Emit compact JSON instead of pretty-printed output.
        #[arg(long)]
        compact: bool,
    },
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared parsers and audit helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Clap parser for `--min-anomaly-score` and `--threshold`: the shared
/// anomaly-score rule (clamped to 0.0..=1.0, NaN refused), the same one the
/// MCP audit tools apply.
fn parse_score_threshold(raw: &str) -> std::result::Result<f64, String> {
    let value: f64 = raw
        .parse()
        .map_err(|_| format!("'{raw}' is not a number"))?;
    phantom_core::analytics::score_threshold(value)
}

/// Clap parser for `--min-confidence`: a score in 0.0..=1.0.
fn parse_min_confidence(raw: &str) -> std::result::Result<f64, String> {
    let value: f64 = raw
        .parse()
        .map_err(|_| format!("'{raw}' is not a number"))?;
    phantom_core::leak_correlation::check_min_confidence(value)
}

/// Load alerting config from the nearest `.phantom.toml`, falling back to
/// a disabled default if no config file is found or it fails to parse.
fn load_alerting_config_from_project_exact() -> Result<(
    PathBuf,
    Option<Vec<u8>>,
    phantom_core::leak_correlation::AlertingConfig,
)> {
    let config_path = std::env::current_dir()?.join(".phantom.toml");
    let before = phantom_core::fs::read_regular_file(&config_path)
        .context("Failed to safely read alerting configuration")?;
    let alerting = match before.as_deref() {
        Some(bytes) => {
            let text = std::str::from_utf8(bytes).context(".phantom.toml is not valid UTF-8")?;
            toml::from_str::<phantom_core::config::PhantomConfig>(text)
                .context("Failed to parse .phantom.toml")?
                .alerting
        }
        None => phantom_core::leak_correlation::AlertingConfig::default(),
    };
    Ok((config_path, before, alerting))
}

fn recheck_optional_regular_file(path: &std::path::Path, expected: Option<&[u8]>) -> Result<()> {
    if phantom_core::fs::read_regular_file(path)
        .context("Failed to recheck alerting configuration")?
        .as_deref()
        != expected
    {
        anyhow::bail!(
            "Alerting configuration changed after terminal review; no alert dispatch was attempted"
        );
    }
    Ok(())
}

fn exact_bytes_digest(bytes: Option<&[u8]>) -> String {
    let mut hasher = Sha256::new();
    match bytes {
        Some(bytes) => {
            hasher.update(b"present\0");
            hasher.update(bytes);
        }
        None => hasher.update(b"absent\0"),
    }
    format!("{:x}", hasher.finalize())
}

fn require_trusted_terminal_audit_effect(plan: &serde_json::Value) -> Result<()> {
    let attached = std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal();
    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    confirm_audit_effect(plan, attached, &mut stdin.lock(), &mut stderr.lock())
}

fn confirm_audit_effect(
    plan: &serde_json::Value,
    attached: bool,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<()> {
    if !attached {
        anyhow::bail!(
            "Audit network or persistence effects require stdin, stdout, and stderr attached to a trusted terminal; no network request was sent and no report or alert record was written"
        );
    }
    let plan_json = serde_json::to_string_pretty(plan)?;
    let challenge = format!(
        "phantom audit authorize {:x}",
        Sha256::digest(plan_json.as_bytes())
    );
    writeln!(writer, "Audit effect plan:\n{plan_json}")?;
    writeln!(writer, "Approve only if this terminal is outside the requesting agent's authority; a same-user shell or agent-controlled PTY can automate this ceremony.")?;
    write!(writer, "Type `{challenge}` to continue: ")?;
    writer.flush()?;
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        anyhow::bail!("Audit effect cancelled: typed confirmation did not match");
    }
    Ok(())
}

/// A no-op alert dispatcher for read-only operations.
pub(crate) struct NullDispatch;

impl phantom_core::leak_correlation::AlertDispatch for NullDispatch {
    fn send_webhook(&self, _url: &str, _payload: &serde_json::Value) -> std::io::Result<()> {
        Ok(())
    }
    fn send_slack(&self, _url: &str, _payload: &serde_json::Value) -> std::io::Result<()> {
        Ok(())
    }
    fn send_pagerduty(
        &self,
        _integration_key: &str,
        _payload: &serde_json::Value,
    ) -> std::io::Result<()> {
        Ok(())
    }
}

/// Format a duration in seconds as a human-readable "X ago" string.
fn human_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Open the audit log for following (`audit tail`, `audit anomalies
/// --realtime`), positioned at its end so only new lines are shown. The log
/// (and a 0700 `~/.phantom`) is created 0600 when absent so a follower can
/// wait for the first event; a symlinked or non-regular log, or a symlinked
/// `~/.phantom`, is refused rather than followed.
fn open_log_for_follow(path: &std::path::Path) -> Result<BufReader<std::fs::File>> {
    let file = phantom_core::audit::open_log_for_follow(path)
        .map_err(|error| anyhow::anyhow!("Cannot open audit log {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::End(0))?;
    Ok(reader)
}

fn resolve_path() -> Result<PathBuf> {
    phantom_core::audit::log_path()
        .map_err(|e| anyhow::anyhow!("Could not resolve home directory to locate audit log: {e}"))
}

/// Audit lines that passed the filters, from a bounded window of the log.
struct MatchedLines {
    lines: Vec<String>,
    /// Lines in the window that were not UTF-8 or not JSON, skipped.
    unparsable: usize,
    /// The log is larger than the window; older lines were not examined.
    window_truncated: bool,
}

/// The matching lines among the newest [`phantom_core::audit::RECENT_WINDOW_BYTES`]
/// of the log. The log is append-only and never rotated, so this no longer
/// reads it whole; chain verification (`phantom audit verify`) still does.
fn read_matching_lines(
    path: &std::path::Path,
    op: Option<&str>,
    name: Option<&str>,
) -> std::io::Result<MatchedLines> {
    read_matching_lines_within(path, op, name, phantom_core::audit::RECENT_WINDOW_BYTES)
}

fn read_matching_lines_within(
    path: &std::path::Path,
    op: Option<&str>,
    name: Option<&str>,
    max_bytes: u64,
) -> std::io::Result<MatchedLines> {
    let recent = phantom_core::audit::read_recent_lines(path, max_bytes)?;
    let mut matched = MatchedLines {
        lines: Vec::new(),
        unparsable: recent.unreadable_lines,
        window_truncated: recent.window_truncated,
    };
    for line in recent.lines {
        // Validate JSON; a malformed line is counted, never echoed.
        if serde_json::from_str::<Value>(&line).is_err() {
            matched.unparsable += 1;
            continue;
        }
        if matches_filters(&line, op, name) {
            matched.lines.push(line);
        }
    }
    Ok(matched)
}

/// Returns true if the raw JSON line passes both op and name filters.
fn matches_filters(line: &str, op: Option<&str>, name: Option<&str>) -> bool {
    if op.is_none() && name.is_none() {
        return true;
    }
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if let Some(filter_op) = op {
        if v["op"].as_str() != Some(filter_op) {
            return false;
        }
    }
    if let Some(filter_name) = name {
        if v["name"].as_str() != Some(filter_name) {
            return false;
        }
    }
    true
}

/// Pretty-print a single JSONL line.
///
/// Format: `[YYYY-MM-DD HH:MM:SS]  op  name  (process pid)`
fn print_event(line: &str) {
    // A closed stdout or stderr ends the tail like println! would.
    write_event(line, &mut std::io::stdout(), &mut std::io::stderr())
        .expect("failed to write audit event");
}

/// One human-readable event line into `out`; a malformed line is reported
/// to `err` and skipped.
fn write_event(line: &str, out: &mut dyn Write, err: &mut dyn Write) -> std::io::Result<()> {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            return writeln!(
                err,
                "{} Skipping malformed line: {}",
                "warn".yellow().bold(),
                line
            );
        }
    };

    let ts_str = v["ts"]
        .as_u64()
        .map(format_unix_ts)
        .unwrap_or_else(|| "?".to_string());

    let op = v["op"].as_str().unwrap_or("?");
    let name = v["name"].as_str().unwrap_or("");
    let process = v["process"].as_str().unwrap_or("?");
    let pid = v["pid"]
        .as_u64()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "?".to_string());

    let name_part = if name.is_empty() {
        String::new()
    } else {
        format!("  {}", name.bold())
    };

    writeln!(
        out,
        "{}  {}{}  {}",
        ts_str.dimmed(),
        op.cyan(),
        name_part,
        format!("({} {})", process, pid).dimmed()
    )
}

/// Format a Unix epoch (seconds) as `YYYY-MM-DD HH:MM:SS` using only std.
fn format_unix_ts(secs: u64) -> String {
    // Days since Unix epoch
    let days = secs / 86400;
    let rem = secs % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    // Gregorian calendar computation (valid for dates after 1970)
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hh, mm, ss
    )
}

/// Convert days-since-Unix-epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

#[cfg(test)]
use analytics::{prepare_analytics_export_in, render_stats_analytics};
#[cfg(test)]
use log::run_show_at;
#[cfg(test)]
use report::render_export_range;

#[cfg(test)]
mod tests;
