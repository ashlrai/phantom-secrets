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
//!                            [--export PATH] [--auto-alert-on-anomaly]

use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use serde_json::Value;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;

// ──────────────────────────────────────────────────────────────────────────────
// Subcommand definition (re-exported so main.rs can use it)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum AuditAction {
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
        /// Only show secrets whose anomaly score is at or above this threshold (0.0–1.0)
        #[arg(long, value_name = "SCORE")]
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
        /// Only export records for secrets whose anomaly score is at or above this threshold
        #[arg(long, value_name = "SCORE")]
        min_anomaly_score: Option<f64>,
    },
    /// Export full audit analytics for external dashboards (Datadog, Grafana, CloudWatch)
    Analytics {
        /// Time window in days (default: 30; 0 = all history)
        #[arg(long, default_value_t = 30)]
        window: u32,
        /// Only include secrets with anomaly score at or above this threshold (0.0–1.0)
        #[arg(long, value_name = "SCORE")]
        min_anomaly_score: Option<f64>,
        /// Output format: json (default) or csv
        #[arg(long, default_value = "json")]
        format: String,
        /// Write output to this file path instead of stdout
        #[arg(long, value_name = "PATH")]
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
        /// Minimum anomaly score (0.0–1.0) at which an alert is emitted (default: 0.5)
        #[arg(long, default_value_t = 0.5, value_name = "SCORE")]
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
    /// Show correlated leak incidents derived from proxy.response_leak audit events.
    ///
    /// Incidents are grouped by (secret, location) within 24-hour windows.
    /// High-confidence incidents (≥ 0.95) indicate the same secret leaked more
    /// than 3 times within an hour — immediate rotation is advised.
    ///
    /// Examples:
    ///   phantom audit incidents
    ///   phantom audit incidents --min-confidence 0.5
    ///   phantom audit incidents
    Incidents {
        /// Only show incidents with confidence ≥ this value (default: 0.5)
        #[arg(long, default_value_t = 0.5, value_name = "SCORE")]
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

    /// Export raw audit log rows filtered by date range, secret, or operation.
    ///
    /// Examples:
    ///   phantom audit export-range --format csv --from 2026-01-01 --to 2026-06-29 > audit.csv
    ///   phantom audit export-range --format json --name OPENAI_API_KEY
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

    /// Show persisted leak-incident alert records from ~/.phantom/leak-alerts.jsonl.
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

    /// Generate a structured compliance report and save to ~/.phantom/reports/.
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
// Entry points called from main.rs
// ──────────────────────────────────────────────────────────────────────────────

pub fn run_show(
    last: usize,
    op: Option<&str>,
    name: Option<&str>,
    json: bool,
    leaked_secrets: bool,
) -> Result<()> {
    let path = resolve_path()?;

    if !path.exists() {
        println!(
            "{}  No audit events yet — set {} to start logging.",
            "->".blue().bold(),
            "PHANTOM_AUDIT=1".cyan()
        );
        return Ok(());
    }

    // --leaked-secrets overrides --op to filter to proxy.response_leak events.
    let effective_op = if leaked_secrets {
        Some("proxy.response_leak")
    } else {
        op
    };

    let lines = read_matching_lines(&path, effective_op, name);

    if lines.is_empty() {
        println!("{}  No matching audit events.", "->".blue().bold());
        return Ok(());
    }

    // Take the last N
    let window: Vec<&str> = lines
        .iter()
        .rev()
        .take(last)
        .rev() // restore chronological order
        .map(String::as_str)
        .collect();

    if json {
        for line in &window {
            println!("{}", line);
        }
    } else {
        for line in &window {
            print_event(line);
        }
    }

    Ok(())
}

pub fn run_tail(op: Option<&str>, name: Option<&str>) -> Result<()> {
    let path = resolve_path()?;

    // Create the file + parent dirs so we can seek even before any events land.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Open (or create) the file and seek to end — we only show new lines.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(&path)?;
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::End(0))?;

    println!(
        "{}  Tailing {} — press Ctrl-C to stop",
        "->".blue().bold(),
        path.display().to_string().dimmed()
    );

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            // No new data — wait and retry
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        }
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if matches_filters(trimmed, op, name) {
            print_event(trimmed);
        }
    }
}

pub fn run_path() -> Result<()> {
    let path = resolve_path()?;
    println!("{}", path.display());
    Ok(())
}

pub fn run_verify(with_context: bool) -> Result<()> {
    let path = resolve_path()?;
    if !path.exists() {
        println!(
            "{}  No audit log found — set {} to start logging.",
            "->".blue().bold(),
            "PHANTOM_AUDIT=1".cyan()
        );
        return Ok(());
    }

    // When --with-context is requested, use the richer verify path.
    if with_context {
        return run_verify_with_context();
    }

    let report = phantom_core::audit::verify_log()
        .map_err(|e| anyhow::anyhow!("Failed to verify audit log: {e}"))?;

    let status = if report.is_clean() {
        "ok".green().bold().to_string()
    } else {
        "FAILED".red().bold().to_string()
    };

    println!(
        "{}  verified: {} · tampered: {} · malformed: {} · sequence: {} · head: {} · legacy: {}",
        status,
        report.verified.to_string().cyan(),
        if report.tampered > 0 {
            report.tampered.to_string().red().bold().to_string()
        } else {
            report.tampered.to_string()
        },
        if report.malformed > 0 {
            report.malformed.to_string().red().bold().to_string()
        } else {
            report.malformed.to_string()
        },
        if report.sequence_errors > 0 {
            report.sequence_errors.to_string().red().bold().to_string()
        } else {
            report.sequence_errors.to_string()
        },
        if report.head_missing {
            "missing".red().bold().to_string()
        } else if report.head_mismatch {
            "mismatch".red().bold().to_string()
        } else {
            "ok".to_string()
        },
        report.legacy.to_string().dimmed(),
    );

    if !report.tampered_lines.is_empty() {
        let line_list: Vec<String> = report
            .tampered_lines
            .iter()
            .map(|n| n.to_string())
            .collect();
        eprintln!(
            "{}  Tampered at line{}: {}",
            "!".red().bold(),
            if report.tampered_lines.len() == 1 {
                ""
            } else {
                "s"
            },
            line_list.join(", ").red()
        );
    }

    if !report.malformed_lines.is_empty() {
        let line_list: Vec<String> = report
            .malformed_lines
            .iter()
            .map(|n| n.to_string())
            .collect();
        eprintln!(
            "{}  Malformed JSON at line{}: {}",
            "!".red().bold(),
            if report.malformed_lines.len() == 1 {
                ""
            } else {
                "s"
            },
            line_list.join(", ").red()
        );
    }

    if !report.sequence_error_lines.is_empty() {
        let line_list: Vec<String> = report
            .sequence_error_lines
            .iter()
            .map(|n| n.to_string())
            .collect();
        eprintln!(
            "{}  Sequence error at line{}: {}",
            "!".red().bold(),
            if report.sequence_error_lines.len() == 1 {
                ""
            } else {
                "s"
            },
            line_list.join(", ").red()
        );
    }

    if report.head_missing {
        eprintln!(
            "{}  Audit head checkpoint is missing; tail truncation cannot be ruled out.",
            "!".red().bold()
        );
    }
    if report.head_mismatch {
        eprintln!(
            "{}  Audit head checkpoint does not match the log tail.",
            "!".red().bold()
        );
    }

    if !report.is_clean() {
        std::process::exit(1);
    }

    Ok(())
}

/// `phantom audit verify --with-context`: decrypt and display `encrypted_context`
/// for every event in the log, providing a forensics-grade view of audit metadata.
fn run_verify_with_context() -> Result<()> {
    let (report, events) = phantom_core::audit::verify_log_with_context()
        .map_err(|e| anyhow::anyhow!("Failed to verify audit log: {e}"))?;

    let status = if report.is_clean() {
        "ok".green().bold().to_string()
    } else {
        "FAILED".red().bold().to_string()
    };

    println!(
        "{}  verified: {} · tampered: {} · malformed: {} · sequence: {} · head: {} · legacy: {}",
        status,
        report.verified.to_string().cyan(),
        if report.tampered > 0 {
            report.tampered.to_string().red().bold().to_string()
        } else {
            report.tampered.to_string()
        },
        if report.malformed > 0 {
            report.malformed.to_string().red().bold().to_string()
        } else {
            report.malformed.to_string()
        },
        if report.sequence_errors > 0 {
            report.sequence_errors.to_string().red().bold().to_string()
        } else {
            report.sequence_errors.to_string()
        },
        if report.head_missing {
            "missing".red().bold().to_string()
        } else if report.head_mismatch {
            "mismatch".red().bold().to_string()
        } else {
            "ok".to_string()
        },
        report.legacy.to_string().dimmed(),
    );

    println!();
    println!("{}  Decrypted context per event:", "->".blue().bold());
    println!();

    for ev in &events {
        let v: serde_json::Value = match serde_json::from_str(&ev.raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ts = v["ts"].as_u64().map(format_unix_ts).unwrap_or_default();
        let op = v["op"].as_str().unwrap_or("?");
        let seq = v["seq"].as_u64().map(|s| s.to_string()).unwrap_or_default();

        print!("  {} [{}] {}", ts.dimmed(), seq.cyan(), op.bold());
        if let Some(name) = v["name"].as_str() {
            print!("  {}", name.bold());
        }
        println!();

        match (&ev.context, &ev.context_error) {
            (Some(ctx), _) => {
                println!(
                    "    {} process={} hostname={} ppid={} cwd={}",
                    "context:".green(),
                    ctx.process_name.cyan(),
                    ctx.hostname.cyan(),
                    ctx.ppid.to_string().cyan(),
                    ctx.cwd.dimmed(),
                );
            }
            (None, Some(err)) => {
                println!("    {} {}", "context error:".yellow(), err.dimmed());
            }
            (None, None) => {
                println!("    {}", "no encrypted context".dimmed());
            }
        }
    }

    if !report.is_clean() {
        std::process::exit(1);
    }

    Ok(())
}

pub fn run_stats(
    json: bool,
    top: usize,
    analytics: bool,
    min_anomaly_score: Option<f64>,
) -> Result<()> {
    // When --analytics is requested (or --min-anomaly-score is provided),
    // delegate to the analytics engine which returns richer per-secret data.
    if analytics || min_anomaly_score.is_some() {
        return run_stats_analytics(json, top, min_anomaly_score);
    }

    let stats = phantom_core::audit::audit_stats()
        .map_err(|e| anyhow::anyhow!("Failed to read audit log: {e}"))?;

    if stats.total_events == 0 {
        println!(
            "{}  No audit events yet — set {} to start logging.",
            "->".blue().bold(),
            "PHANTOM_AUDIT=1".cyan()
        );
        return Ok(());
    }

    let secrets = if top > 0 && top < stats.secrets.len() {
        &stats.secrets[..top]
    } else {
        &stats.secrets[..]
    };

    if json {
        // Emit a JSON object with the full stats, limited secrets slice.
        let out = serde_json::json!({
            "total_events": stats.total_events,
            "secret_events": stats.secret_events,
            "first_event_ts": stats.first_event_ts,
            "last_event_ts": stats.last_event_ts,
            "secrets": secrets,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    // Header
    println!(
        "{}  {} total events · {} name a secret · log covers {}",
        "->".blue().bold(),
        stats.total_events.to_string().cyan(),
        stats.secret_events.to_string().cyan(),
        match (stats.first_event_ts, stats.last_event_ts) {
            (Some(f), Some(l)) => format!(
                "{} → {}",
                format_unix_ts(f).dimmed(),
                format_unix_ts(l).dimmed()
            ),
            _ => "unknown range".dimmed().to_string(),
        }
    );

    if secrets.is_empty() {
        println!("{}  No per-secret events recorded.", "->".blue().bold());
        return Ok(());
    }

    println!();

    // Column widths
    let name_w = secrets
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "  {:<name_w$}  {:>6}  {:>6}  {:>7}  {:>7}  {}",
        "SECRET".bold(),
        "TOTAL".bold(),
        "STORES".bold(),
        "FETCHES".bold(),
        "DELETES".bold(),
        "LAST SEEN".bold(),
        name_w = name_w,
    );
    println!("  {}", "-".repeat(name_w + 38));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for s in secrets {
        let age = if s.last_seen_ts > 0 {
            human_age(now.saturating_sub(s.last_seen_ts))
        } else {
            "unknown".to_string()
        };

        // Colour-code: yellow if not seen in >7 days, red if >30 days.
        let age_str = if s.last_seen_ts > 0 {
            let secs_ago = now.saturating_sub(s.last_seen_ts);
            if secs_ago > 30 * 86400 {
                age.red().to_string()
            } else if secs_ago > 7 * 86400 {
                age.yellow().to_string()
            } else {
                age.dimmed().to_string()
            }
        } else {
            age.dimmed().to_string()
        };

        println!(
            "  {:<name_w$}  {:>6}  {:>6}  {:>7}  {:>7}  {}",
            s.name.bold(),
            s.total,
            s.stores,
            s.retrieves,
            s.deletes,
            age_str,
            name_w = name_w,
        );
    }

    Ok(())
}

/// Run the analytics-enhanced stats path (with anomaly scores).
fn run_stats_analytics(json: bool, top: usize, min_anomaly_score: Option<f64>) -> Result<()> {
    let report = phantom_core::analytics::compute_analytics(phantom_core::analytics::Period::All)
        .map_err(|e| anyhow::anyhow!("Failed to compute analytics: {e}"))?;

    if report.secrets.is_empty() {
        println!(
            "{}  No audit events yet — set {} to start logging.",
            "->".blue().bold(),
            "PHANTOM_AUDIT=1".cyan()
        );
        return Ok(());
    }

    let mut secrets: Vec<&phantom_core::analytics::SecretAnalytics> = report
        .secrets
        .iter()
        .filter(|s| min_anomaly_score.is_none_or(|min| s.anomaly_score >= min))
        .collect();

    if top > 0 && top < secrets.len() {
        secrets.truncate(top);
    }

    if json {
        let out = serde_json::json!({
            "generated_at": report.generated_at,
            "secrets": secrets,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    // Human-readable table
    println!(
        "{}  Analytics for {} secret(s){}",
        "->".blue().bold(),
        secrets.len(),
        min_anomaly_score
            .map(|s| format!(" (anomaly_score ≥ {s:.2})"))
            .unwrap_or_default()
            .dimmed()
    );
    println!();

    let name_w = secrets
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "  {:<name_w$}  {:>7}  {:>8}  {:>8}  {:>8}  {:>7}",
        "SECRET".bold(),
        "ACCESSES".bold(),
        "AVG/DAY".bold(),
        "MAX/DAY".bold(),
        "MIN/DAY".bold(),
        "ANOMALY".bold(),
        name_w = name_w,
    );
    println!("  {}", "-".repeat(name_w + 46));

    for s in &secrets {
        let score_str = if s.anomaly_score >= 0.6 {
            format!("{:.2}", s.anomaly_score).red().bold().to_string()
        } else if s.anomaly_score >= 0.4 {
            format!("{:.2}", s.anomaly_score).yellow().to_string()
        } else {
            format!("{:.2}", s.anomaly_score).dimmed().to_string()
        };

        println!(
            "  {:<name_w$}  {:>7}  {:>8.2}  {:>8}  {:>8}  {:>7}",
            s.name.bold(),
            s.access_count,
            s.daily_avg,
            s.max_daily,
            s.min_daily,
            score_str,
            name_w = name_w,
        );
    }

    Ok(())
}

pub fn run_export(format: &str, period: &str, min_anomaly_score: Option<f64>) -> Result<()> {
    let period = phantom_core::analytics::Period::parse(period)
        .ok_or_else(|| anyhow::anyhow!("Invalid period '{period}'. Use: 7d, 30d, or all"))?;

    if !matches!(format, "csv" | "json") {
        return Err(anyhow::anyhow!(
            "Invalid format '{format}'. Use: csv or json"
        ));
    }

    let records = phantom_core::analytics::export_records(period, min_anomaly_score)
        .map_err(|e| anyhow::anyhow!("Failed to export records: {e}"))?;

    if records.is_empty() {
        eprintln!(
            "{}  No access records found for the requested period/filter.",
            "->".blue().bold()
        );
        return Ok(());
    }

    match format {
        "csv" => {
            print!("{}", phantom_core::analytics::records_to_csv(&records));
        }
        "json" => {
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// `phantom audit analytics` — full analytics export for external dashboards.
///
/// Steps:
/// 1. Read audit log for the requested window.
/// 2. Bucket events by calendar day per secret.
/// 3. Compute analytics (anomaly scores, daily stats) per secret.
/// 4. Serialize as JSON or CSV.
/// 5. Write to stdout or `--export PATH`.
/// 6. If `--auto-alert-on-anomaly` is set, exit 1 if any secret exceeds threshold.
pub fn run_analytics(
    window: u32,
    min_anomaly_score: Option<f64>,
    format: &str,
    export: Option<&str>,
    auto_alert_on_anomaly: bool,
) -> Result<()> {
    use phantom_core::analytics::{compute_analytics, export_records, records_to_csv, Period};

    if !matches!(format, "json" | "csv") {
        return Err(anyhow::anyhow!(
            "Invalid format '{}'. Use: json or csv",
            format
        ));
    }

    let period = match window {
        0 => Period::All,
        1..=7 => Period::Days7,
        _ => Period::Days30,
    };

    let report = compute_analytics(period)
        .map_err(|e| anyhow::anyhow!("Failed to compute analytics: {e}"))?;

    let analytics: Vec<&phantom_core::analytics::SecretAnalytics> = report
        .secrets
        .iter()
        .filter(|s| min_anomaly_score.is_none_or(|min| s.anomaly_score >= min))
        .collect();

    let records = export_records(period, min_anomaly_score)
        .map_err(|e| anyhow::anyhow!("Failed to export records: {e}"))?;

    // Build the output string.
    let output = if format == "csv" {
        records_to_csv(&records)
    } else {
        // Build daily bucket time-series for BI tools.
        let mut daily_buckets: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, u64>,
        > = std::collections::BTreeMap::new();
        for rec in &records {
            let iso = phantom_core::analytics::unix_to_iso8601(rec.ts / 86400 * 86400);
            let day_key = iso[..10].to_string(); // YYYY-MM-DD
            *daily_buckets
                .entry(rec.name.clone())
                .or_default()
                .entry(day_key)
                .or_insert(0) += 1;
        }
        let time_series: Vec<serde_json::Value> = daily_buckets
            .iter()
            .map(|(name, days)| {
                let buckets: Vec<serde_json::Value> = days
                    .iter()
                    .map(|(day, count)| serde_json::json!({"date": day, "count": count}))
                    .collect();
                serde_json::json!({"name": name, "daily_buckets": buckets})
            })
            .collect();

        let out = serde_json::json!({
            "generated_at": report.generated_at,
            "window_days": window,
            "analytics": analytics,
            "records": records,
            "time_series": time_series,
        });
        serde_json::to_string_pretty(&out)?
    };

    // Write output.
    if let Some(path) = export {
        std::fs::write(path, &output)
            .map_err(|e| anyhow::anyhow!("Failed to write export file '{path}': {e}"))?;
        eprintln!(
            "{}  Analytics exported to {}",
            "->".blue().bold(),
            path.cyan()
        );
    } else {
        print!("{}", output);
        // Ensure trailing newline for JSON (CSV already has one).
        if format == "json" && !output.ends_with('\n') {
            println!();
        }
    }

    // CI gate: exit non-zero if any secret exceeds anomaly threshold.
    if auto_alert_on_anomaly {
        let threshold = min_anomaly_score.unwrap_or(0.5);
        let flagged: Vec<&str> = analytics
            .iter()
            .filter(|s| s.anomaly_score >= threshold)
            .map(|s| s.name.as_str())
            .collect();
        if !flagged.is_empty() {
            eprintln!(
                "{}  {} secret(s) exceed anomaly threshold {:.2}: {}",
                "ALERT".red().bold(),
                flagged.len(),
                threshold,
                flagged.join(", ").red()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

/// `phantom audit anomalies [--realtime] [--threshold F]`
///
/// Without `--realtime`: performs a one-shot windowed anomaly check and prints
/// any secrets whose score meets `threshold`.
///
/// With `--realtime`: tails the audit log indefinitely. After each new line is
/// appended, re-evaluates all (or the named) secret's windowed metrics and
/// emits an alert line whenever the score crosses `threshold`.
pub fn run_anomalies(
    realtime: bool,
    threshold: f64,
    name_filter: Option<&str>,
    max_accesses_per_hour: Option<u64>,
    max_quiet_days: Option<u64>,
    json_output: bool,
) -> Result<()> {
    use phantom_core::analytics::{compute_windowed_anomalies, AuditThresholdConfig};

    let threshold = threshold.clamp(0.0, 1.0);

    // Build per-call threshold config from CLI flags (if any).
    let thresholds = if max_accesses_per_hour.is_some() || max_quiet_days.is_some() {
        Some(AuditThresholdConfig {
            max_accesses_per_hour,
            max_consecutive_quiet_days: max_quiet_days,
            alert_on_anomaly_score: Some(threshold),
        })
    } else {
        None
    };

    /// Emit one result line to stdout.
    fn emit(r: &phantom_core::analytics::WindowedAnomalyResult, json_output: bool) {
        if json_output {
            let v = serde_json::json!({
                "name": r.name,
                "anomaly_score": r.anomaly_score,
                "alert": r.alert,
                "reason": r.reason,
                "accesses_last_hour": r.accesses_last_hour,
                "max_quiet_gap_days": r.max_quiet_gap_days,
            });
            println!("{}", v);
        } else {
            let score_str = if r.anomaly_score >= 0.7 {
                format!("{:.2}", r.anomaly_score).red().bold().to_string()
            } else if r.anomaly_score >= 0.5 {
                format!("{:.2}", r.anomaly_score).yellow().to_string()
            } else {
                format!("{:.2}", r.anomaly_score).dimmed().to_string()
            };

            let alert_tag = if r.alert {
                " [ALERT]".red().bold().to_string()
            } else {
                String::new()
            };

            println!(
                "{}  {}  score={}  per_hour={}  quiet_gap={}d  {}{}",
                "->".blue().bold(),
                r.name.bold(),
                score_str,
                r.accesses_last_hour,
                r.max_quiet_gap_days,
                r.reason.dimmed(),
                alert_tag,
            );
        }
    }

    if !realtime {
        // One-shot mode.
        let results = compute_windowed_anomalies(name_filter, thresholds.as_ref(), threshold)
            .map_err(|e| anyhow::anyhow!("Failed to compute anomalies: {e}"))?;

        if results.is_empty() {
            if !json_output {
                println!(
                    "{}  No anomalies detected (threshold={:.2}). Set {} to generate audit events.",
                    "->".blue().bold(),
                    threshold,
                    "PHANTOM_AUDIT=1".cyan()
                );
            } else {
                println!("[]");
            }
            return Ok(());
        }

        if json_output {
            let out: Vec<serde_json::Value> = results
                .iter()
                .filter(|r| r.anomaly_score >= threshold)
                .map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "anomaly_score": r.anomaly_score,
                        "alert": r.alert,
                        "reason": r.reason,
                        "accesses_last_hour": r.accesses_last_hour,
                        "max_quiet_gap_days": r.max_quiet_gap_days,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            let flagged: Vec<_> = results
                .iter()
                .filter(|r| r.anomaly_score >= threshold)
                .collect();
            if flagged.is_empty() {
                println!(
                    "{}  No secrets exceed threshold {:.2}.",
                    "->".blue().bold(),
                    threshold
                );
                return Ok(());
            }
            for r in &flagged {
                emit(r, false);
            }
        }
        return Ok(());
    }

    // Real-time tail mode.
    let log_path = phantom_core::audit::log_path()
        .map_err(|e| anyhow::anyhow!("Could not resolve audit log path: {e}"))?;

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(&log_path)?;

    let mut reader = std::io::BufReader::new(file);
    // Seek to end — only process new lines.
    use std::io::Seek;
    reader.seek(std::io::SeekFrom::End(0))?;

    if !json_output {
        println!(
            "{}  Tailing {} for anomalies (threshold={:.2}) — Ctrl-C to stop",
            "->".blue().bold(),
            log_path.display().to_string().dimmed(),
            threshold
        );
    }

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            std::thread::sleep(std::time::Duration::from_millis(200));
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse the new event to extract the secret name — skip non-matching.
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let event_name = v
            .get("name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        // If we're filtering by name and this event doesn't match, skip.
        if let Some(filter) = name_filter {
            if event_name.as_deref() != Some(filter) {
                continue;
            }
        }

        // Re-evaluate windowed anomalies for the affected secret (or all if unfiltered).
        let check_name = name_filter.or(event_name.as_deref());
        let results = compute_windowed_anomalies(check_name, thresholds.as_ref(), threshold)
            .unwrap_or_default();

        for r in results.iter().filter(|r| r.anomaly_score >= threshold) {
            emit(r, json_output);
        }
    }
}

pub fn run_incidents(min_confidence: f64, json: bool, auto_rotate_on_high: bool) -> Result<()> {
    use phantom_core::leak_correlation::LeakCorrelationEngine;

    if auto_rotate_on_high {
        anyhow::bail!(
            "--auto-rotate-on-high is deprecated and disabled: remapping a local phm_ token does not rotate the leaked provider credential and must not clear an incident. Review the incident, rotate at the provider, then store the replacement from a trusted terminal. Automated live provider issuance is disabled."
        );
    }

    let engine = LeakCorrelationEngine::new()
        .map_err(|e| anyhow::anyhow!("Cannot initialise leak correlation engine: {e}"))?;

    // Run correlation over the last 24 h of audit events (persists new incidents).
    let _ = engine.run(); // best-effort; ignore new-incident errors

    // Retrieve active incidents meeting the confidence threshold.
    let incidents = engine
        .active_incidents(min_confidence)
        .map_err(|e| anyhow::anyhow!("Failed to read leak incidents: {e}"))?;

    if incidents.is_empty() {
        if json {
            println!("[]");
        } else {
            println!(
                "{}  No active leak incidents (min_confidence={:.2}). \
                 Set {} to enable audit logging.",
                "->".blue().bold(),
                min_confidence,
                "PHANTOM_AUDIT=1".cyan()
            );
        }
        return Ok(());
    }

    if json {
        let out = serde_json::json!({
            "incidents": incidents,
            "provider_credentials_rotated": [],
        });
        let s = serde_json::to_string_pretty(&out)
            .map_err(|e| anyhow::anyhow!("Serialisation error: {e}"))?;
        println!("{}", s);
        return Ok(());
    }

    println!(
        "{}  {} active leak incident(s) (confidence ≥ {:.2})",
        "->".blue().bold(),
        incidents.len().to_string().red().bold(),
        min_confidence,
    );
    println!();

    // ── Table header ──────────────────────────────────────────────────────────
    println!(
        "  {:<28}  {:<10}  {:<22}  {:<22}  {}",
        "Name".bold(),
        "Confidence".bold(),
        "FirstSeen".bold(),
        "LastSeen".bold(),
        "Status".bold(),
    );
    println!("  {}", "-".repeat(100).dimmed());

    for inc in &incidents {
        let confidence_str = if inc.confidence >= 0.9 {
            format!("{:.2}", inc.confidence).red().bold().to_string()
        } else {
            format!("{:.2}", inc.confidence).yellow().to_string()
        };

        let status = if inc.confidence >= 0.9 {
            "CRITICAL".red().bold().to_string()
        } else {
            "active".yellow().to_string()
        };

        println!(
            "  {:<28}  {:<10}  {:<22}  {:<22}  {}",
            inc.secret_name.bold(),
            confidence_str,
            format_unix_ts(inc.first_seen_ts),
            format_unix_ts(inc.last_seen_ts),
            status,
        );
    }
    println!();

    // A provider credential must be replaced before the incident is resolved.
    for inc in &incidents {
        if inc.confidence >= 0.9 {
            println!(
                "  {}  {}",
                "remediation:".yellow().bold(),
                inc.remediation.dimmed(),
            );
        }
    }

    Ok(())
}

/// `phantom audit alerts [--last N] [--backfill] [--json]`
///
/// Lists persisted leak-incident alert records from `~/.phantom/leak-alerts.jsonl`.
/// With `--backfill`, re-runs the correlation engine against the audit log first
/// and emits any new alerts via configured backends before listing.
pub fn run_alerts(last: usize, backfill: bool, json: bool) -> Result<()> {
    use phantom_core::leak_correlation::{
        AlertingConfig, HttpAlertDispatch, LeakCorrelationEngine, LeakIncidentAlerter,
    };

    // Resolve home dir for the alerts file.
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .map_err(|_| anyhow::anyhow!("Cannot resolve home directory"))?;
    let alerts_path = home.join(".phantom").join("leak-alerts.jsonl");

    if backfill {
        // Re-run correlation to pick up any new incidents.
        let engine = LeakCorrelationEngine::new()
            .map_err(|e| anyhow::anyhow!("Cannot initialise leak correlation engine: {e}"))?;
        let incidents = engine
            .run()
            .map_err(|e| anyhow::anyhow!("Correlation engine failed: {e}"))?;

        if !incidents.is_empty() {
            // Load alerting config from .phantom.toml if present, else use defaults.
            let alerting_config = load_alerting_config_from_project();
            let alerter = LeakIncidentAlerter::with_path(
                alerting_config,
                alerts_path.clone(),
                Box::new(HttpAlertDispatch),
            );
            let new_alerts = alerter
                .process_incidents(&incidents)
                .map_err(|e| anyhow::anyhow!("Alert dispatch failed: {e}"))?;
            if !new_alerts.is_empty() && !json {
                println!(
                    "{}  Emitted {} new alert(s) via configured backends.",
                    "->".blue().bold(),
                    new_alerts.len().to_string().green().bold()
                );
            }
        }
    }

    // Load alerts from disk via a dummy alerter (no backends needed for read).
    let dummy_config = AlertingConfig {
        enabled: false,
        min_confidence: 0.0,
        backends: vec![],
    };
    let alerter = LeakIncidentAlerter::with_path(
        dummy_config,
        alerts_path,
        Box::new(crate::commands::audit::NullDispatch),
    );

    let alerts = alerter
        .load_recent_alerts(last)
        .map_err(|e| anyhow::anyhow!("Failed to read alerts: {e}"))?;

    if alerts.is_empty() {
        if json {
            println!("[]");
        } else {
            println!(
                "{}  No leak alerts found. Run with {} to enable alerting.",
                "->".blue().bold(),
                "`phantom audit alerts --backfill`".cyan()
            );
        }
        return Ok(());
    }

    if json {
        let out = serde_json::to_string_pretty(&alerts)
            .map_err(|e| anyhow::anyhow!("Serialisation error: {e}"))?;
        println!("{}", out);
        return Ok(());
    }

    println!(
        "{}  {} leak alert(s) (most recent {} shown)",
        "->".blue().bold(),
        alerts.len().to_string().red().bold(),
        last.min(alerts.len()),
    );
    println!();

    for alert in &alerts {
        let confidence_str = if alert.confidence >= 0.9 {
            format!("{:.2}", alert.confidence).red().bold().to_string()
        } else {
            format!("{:.2}", alert.confidence).yellow().to_string()
        };

        println!(
            "  {}  secret={}  location={}  confidence={}  events={}  backends={}",
            format_unix_ts(alert.alerted_at).dimmed(),
            alert.secret_name.bold(),
            alert.location_label.cyan(),
            confidence_str,
            alert.event_count,
            alert.backends_notified.join(",").dimmed(),
        );
        println!(
            "    {}  {}",
            "remediation:".yellow().bold(),
            alert.remediation.dimmed(),
        );
        println!();
    }

    Ok(())
}

/// Load alerting config from the nearest `.phantom.toml`, falling back to
/// a disabled default if no config file is found or it fails to parse.
fn load_alerting_config_from_project() -> phantom_core::leak_correlation::AlertingConfig {
    // Walk up from cwd looking for .phantom.toml
    if let Ok(cwd) = std::env::current_dir() {
        let config_path = cwd.join(".phantom.toml");
        if config_path.exists() {
            if let Ok(cfg) = phantom_core::config::PhantomConfig::load(&config_path) {
                return cfg.alerting;
            }
        }
    }
    phantom_core::leak_correlation::AlertingConfig::default()
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

/// `phantom audit export-range` — export audit rows with date-range + field filters.
///
/// Writes CSV or JSON to stdout. Rows include: timestamp, datetime, operation,
/// secret_name, pid, hostname (decrypted from encrypted_context if available), severity.
pub fn run_export_range(
    format: &str,
    from: &str,
    to: &str,
    name: Option<&str>,
    op: Option<&str>,
    pid: Option<u64>,
) -> Result<()> {
    use phantom_core::audit_export::{
        parse_date_to_ts, parse_date_to_ts_end, AuditExporter, ExportFilter,
    };

    if !matches!(format, "csv" | "json") {
        return Err(anyhow::anyhow!(
            "Invalid format '{}'. Use: csv or json",
            format
        ));
    }

    let exporter =
        AuditExporter::new().map_err(|e| anyhow::anyhow!("Failed to initialise exporter: {e}"))?;

    let filter = ExportFilter {
        from_ts: parse_date_to_ts(from),
        to_ts: parse_date_to_ts_end(to),
        secret_name: name.map(|s| s.to_string()),
        operation: op.map(|s| s.to_string()),
        pid,
    };

    let rows = exporter
        .export_rows(&filter)
        .map_err(|e| anyhow::anyhow!("Failed to export audit rows: {e}"))?;

    if rows.is_empty() {
        eprintln!(
            "{}  No audit rows match the requested filters.",
            "->".blue().bold()
        );
        return Ok(());
    }

    match format {
        "csv" => print!("{}", AuditExporter::rows_to_csv(&rows)),
        "json" => {
            let json = AuditExporter::rows_to_json(&rows)
                .map_err(|e| anyhow::anyhow!("Serialisation error: {e}"))?;
            println!("{}", json);
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// `phantom audit report --type compliance` — generate and optionally save a
/// structured compliance report.
///
/// Prints the JSON report to stdout. With `--save`, also persists it to
/// `~/.phantom/reports/report-<ts>.json`.
pub fn run_report(
    report_type: &str,
    from: &str,
    to: &str,
    save: bool,
    compact: bool,
) -> Result<()> {
    use phantom_core::audit_export::{parse_date_to_ts, parse_date_to_ts_end, AuditExporter};

    if report_type != "compliance" {
        return Err(anyhow::anyhow!(
            "Unknown report type '{}'. Supported: compliance",
            report_type
        ));
    }

    let exporter =
        AuditExporter::new().map_err(|e| anyhow::anyhow!("Failed to initialise exporter: {e}"))?;

    let from_ts = parse_date_to_ts(from);
    let to_ts = parse_date_to_ts_end(to);

    let report = exporter
        .generate_compliance_report(from_ts, to_ts)
        .map_err(|e| anyhow::anyhow!("Failed to generate compliance report: {e}"))?;

    // Serialise.
    let json = if compact {
        serde_json::to_string(&report).map_err(|e| anyhow::anyhow!("Serialisation error: {e}"))?
    } else {
        serde_json::to_string_pretty(&report)
            .map_err(|e| anyhow::anyhow!("Serialisation error: {e}"))?
    };

    println!("{}", json);

    if save {
        let path = exporter
            .save_report(&report)
            .map_err(|e| anyhow::anyhow!("Failed to save report: {e}"))?;
        eprintln!(
            "{}  Report saved to {}",
            "->".blue().bold(),
            path.display().to_string().cyan()
        );
    }

    Ok(())
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

fn resolve_path() -> Result<PathBuf> {
    phantom_core::audit::log_path()
        .map_err(|e| anyhow::anyhow!("Could not resolve home directory to locate audit log: {e}"))
}

/// Read all lines from the file, skip malformed JSON with a stderr warning,
/// and return only lines that match the given filters.
fn read_matching_lines(path: &PathBuf, op: Option<&str>, name: Option<&str>) -> Vec<String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{} Failed to open audit log: {}", "warn".yellow().bold(), e);
            return vec![];
        }
    };
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for (i, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "{} Skipping unreadable line {}: {}",
                    "warn".yellow().bold(),
                    i + 1,
                    e
                );
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Validate JSON — skip malformed lines
        match serde_json::from_str::<Value>(trimmed) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{} Skipping malformed JSON on line {}: {}",
                    "warn".yellow().bold(),
                    i + 1,
                    e
                );
                continue;
            }
        }
        if matches_filters(trimmed, op, name) {
            out.push(trimmed.to_string());
        }
    }
    out
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
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "{} Skipping malformed line: {}",
                "warn".yellow().bold(),
                line
            );
            return;
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

    println!(
        "{}  {}{}  {}",
        ts_str.dimmed(),
        op.cyan(),
        name_part,
        format!("({} {})", process, pid).dimmed()
    );
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

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_fixture(dir: &std::path::Path, lines: &[&str]) -> PathBuf {
        let path = dir.join("audit.log");
        let mut f = std::fs::File::create(&path).unwrap();
        for line in lines {
            writeln!(f, "{}", line).unwrap();
        }
        path
    }

    const LINE_STORE: &str = r#"{"ts":1700000000,"op":"vault.store","name":"OPENAI_API_KEY","process":"phantom","pid":1}"#;
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
    fn filter_by_op() {
        let tmp = tempdir().unwrap();
        let path = write_fixture(
            tmp.path(),
            &[LINE_STORE, LINE_RETRIEVE, LINE_PUSH, LINE_STRIPE],
        );
        let results = read_matching_lines(&path, Some("vault.store"), None);
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
        let results = read_matching_lines(&path, None, Some("OPENAI_API_KEY"));
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
        let results = read_matching_lines(&path, Some("vault.store"), Some("OPENAI_API_KEY"));
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
        // Should return 2 valid lines, not crash
        let results = read_matching_lines(&path, None, None);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn empty_file_returns_no_lines() {
        let tmp = tempdir().unwrap();
        let path = write_fixture(tmp.path(), &[]);
        let results = read_matching_lines(&path, None, None);
        assert!(results.is_empty());
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
}
