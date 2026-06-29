//! `phantom audit` subcommands for reading the JSONL audit log.
//!
//! Actions:
//!   phantom audit show    [--last N] [--op OP] [--name NAME] [--json]
//!   phantom audit tail    [--op OP] [--name NAME]
//!   phantom audit path
//!   phantom audit verify
//!   phantom audit stats   [--json] [--top N] [--analytics] [--min-anomaly-score F]
//!   phantom audit export  [--format csv|json] [--period 7d|30d] [--min-anomaly-score F]

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
}

// ──────────────────────────────────────────────────────────────────────────────
// Entry points called from main.rs
// ──────────────────────────────────────────────────────────────────────────────

pub fn run_show(last: usize, op: Option<&str>, name: Option<&str>, json: bool) -> Result<()> {
    let path = resolve_path()?;

    if !path.exists() {
        println!(
            "{}  No audit events yet — set {} to start logging.",
            "->".blue().bold(),
            "PHANTOM_AUDIT=1".cyan()
        );
        return Ok(());
    }

    let lines = read_matching_lines(&path, op, name);

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

        print!(
            "  {} [{}] {}",
            ts.dimmed(),
            seq.cyan(),
            op.bold()
        );
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
            (Some(f), Some(l)) =>
                format!("{} → {}", format_unix_ts(f).dimmed(), format_unix_ts(l).dimmed()),
            _ => "unknown range".dimmed().to_string(),
        }
    );

    if secrets.is_empty() {
        println!("{}  No per-secret events recorded.", "->".blue().bold());
        return Ok(());
    }

    println!();

    // Column widths
    let name_w = secrets.iter().map(|s| s.name.len()).max().unwrap_or(4).max(4);
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
fn run_stats_analytics(
    json: bool,
    top: usize,
    min_anomaly_score: Option<f64>,
) -> Result<()> {
    let report =
        phantom_core::analytics::compute_analytics(phantom_core::analytics::Period::All)
            .map_err(|e| anyhow::anyhow!("Failed to compute analytics: {e}"))?;

    if report.secrets.is_empty() {
        println!(
            "{}  No audit events yet — set {} to start logging.",
            "->".blue().bold(),
            "PHANTOM_AUDIT=1".cyan()
        );
        return Ok(());
    }

    let mut secrets: Vec<&phantom_core::analytics::SecretAnalytics> = report.secrets.iter()
        .filter(|s| {
            min_anomaly_score.map_or(true, |min| s.anomaly_score >= min)
        })
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

    let name_w = secrets.iter().map(|s| s.name.len()).max().unwrap_or(4).max(4);
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
}
