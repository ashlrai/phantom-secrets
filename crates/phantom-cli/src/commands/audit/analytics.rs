use super::*;

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

    let secrets = if top > 0 && top < stats.secrets.len() {
        &stats.secrets[..top]
    } else {
        &stats.secrets[..]
    };

    if stats.total_events == 0 && !json {
        println!(
            "{}  No audit events yet — set {} to start logging.",
            "->".blue().bold(),
            "PHANTOM_AUDIT=1".cyan()
        );
        return Ok(());
    }

    if json {
        if stats.total_events == 0 {
            eprintln!(
                "{}  No audit events yet — set {} to start logging.",
                "->".blue().bold(),
                "PHANTOM_AUDIT=1".cyan()
            );
        }
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

/// Rows shown by `phantom audit stats --analytics`, after the anomaly-score
/// floor and `--top` limit.
fn select_analytics_rows(
    report: &phantom_core::analytics::AnalyticsReport,
    top: usize,
    min_anomaly_score: Option<f64>,
) -> Vec<&phantom_core::analytics::SecretAnalytics> {
    let mut rows: Vec<&phantom_core::analytics::SecretAnalytics> = report
        .secrets
        .iter()
        .filter(|s| min_anomaly_score.is_none_or(|min| s.anomaly_score >= min))
        .collect();
    if top > 0 && top < rows.len() {
        rows.truncate(top);
    }
    rows
}

/// The `phantom audit stats --analytics --json` envelope. Same shape whether
/// or not any events exist.
fn stats_analytics_json(
    report: &phantom_core::analytics::AnalyticsReport,
    rows: &[&phantom_core::analytics::SecretAnalytics],
) -> Value {
    serde_json::json!({
        "generated_at": report.generated_at,
        "secrets": rows,
    })
}

/// Run the analytics-enhanced stats path (with anomaly scores).
fn run_stats_analytics(json: bool, top: usize, min_anomaly_score: Option<f64>) -> Result<()> {
    let report = phantom_core::analytics::compute_analytics(phantom_core::analytics::Period::All)
        .map_err(|e| anyhow::anyhow!("Failed to compute analytics: {e}"))?;
    render_stats_analytics(
        &report,
        json,
        top,
        min_anomaly_score,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}

/// Render `phantom audit stats --analytics`. With `--json`, `out` always
/// carries the `{generated_at, secrets}` envelope (an empty `secrets` list
/// when nothing is logged) and the human hint goes to `err`.
pub(super) fn render_stats_analytics(
    report: &phantom_core::analytics::AnalyticsReport,
    json: bool,
    top: usize,
    min_anomaly_score: Option<f64>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<()> {
    if report.secrets.is_empty() {
        let hint = format!(
            "{}  No audit events yet — set {} to start logging.",
            "->".blue().bold(),
            "PHANTOM_AUDIT=1".cyan()
        );
        if !json {
            writeln!(out, "{hint}")?;
            return Ok(());
        }
        // Keep stdout machine-readable: the hint goes to stderr and the
        // normal envelope is emitted with an empty `secrets` list below.
        writeln!(err, "{hint}")?;
    }

    let secrets = select_analytics_rows(report, top, min_anomaly_score);

    if json {
        let envelope = stats_analytics_json(report, &secrets);
        writeln!(out, "{}", serde_json::to_string_pretty(&envelope)?)?;
        return Ok(());
    }

    // Human-readable table
    writeln!(
        out,
        "{}  Analytics for {} secret(s){}",
        "->".blue().bold(),
        secrets.len(),
        min_anomaly_score
            .map(|s| format!(" (anomaly_score ≥ {s:.2})"))
            .unwrap_or_default()
            .dimmed()
    )?;
    writeln!(out)?;

    let name_w = secrets
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    writeln!(
        out,
        "  {:<name_w$}  {:>7}  {:>8}  {:>8}  {:>8}  {:>7}",
        "SECRET".bold(),
        "ACCESSES".bold(),
        "AVG/DAY".bold(),
        "MAX/DAY".bold(),
        "MIN/DAY".bold(),
        "ANOMALY".bold(),
        name_w = name_w,
    )?;
    writeln!(out, "  {}", "-".repeat(name_w + 46))?;

    for s in &secrets {
        let score_str = if s.anomaly_score >= 0.6 {
            format!("{:.2}", s.anomaly_score).red().bold().to_string()
        } else if s.anomaly_score >= 0.4 {
            format!("{:.2}", s.anomaly_score).yellow().to_string()
        } else {
            format!("{:.2}", s.anomaly_score).dimmed().to_string()
        };

        writeln!(
            out,
            "  {:<name_w$}  {:>7}  {:>8.2}  {:>8}  {:>8}  {:>7}",
            s.name.bold(),
            s.access_count,
            s.daily_avg,
            s.max_daily,
            s.min_daily,
            score_str,
            name_w = name_w,
        )?;
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
        // Keep stdout machine-readable: an empty JSON array for json; csv
        // keeps its previous empty-stdout behavior.
        if format == "json" {
            println!("[]");
        }
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
    use phantom_core::analytics::{export_analytics, records_to_csv, Period};

    if !matches!(format, "json" | "csv") {
        return Err(anyhow::anyhow!(
            "Invalid format '{}'. Use: json or csv",
            format
        ));
    }

    // Bind an absent, project-local destination before reading the audit log.
    // A path that appears while analytics are computed is then rejected by the
    // exact-before publication below instead of being overwritten.
    let export_plan = export.map(prepare_analytics_export).transpose()?;

    let period = Period::from_window_days(window);

    // One read of the log against one clock reading, so the summary and the
    // records describe the same events.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let phantom_core::analytics::AnalyticsExport { report, records } =
        export_analytics(period, min_anomaly_score, now)
            .map_err(|e| anyhow::anyhow!("Failed to compute analytics: {e}"))?;

    let analytics: Vec<&phantom_core::analytics::SecretAnalytics> = report
        .secrets
        .iter()
        .filter(|s| min_anomaly_score.is_none_or(|min| s.anomaly_score >= min))
        .collect();

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

    const MAX_ANALYTICS_EXPORT_BYTES: usize = 64 * 1024 * 1024;
    if output.len() > MAX_ANALYTICS_EXPORT_BYTES {
        anyhow::bail!(
            "Analytics export is {} bytes; refusing output larger than {} bytes",
            output.len(),
            MAX_ANALYTICS_EXPORT_BYTES
        );
    }

    // Write output.
    if let Some(plan) = export_plan {
        plan.commit(output.as_bytes())?;
        eprintln!(
            "{}  Analytics exported to {}",
            "->".blue().bold(),
            plan.path.display().to_string().cyan()
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

#[derive(Debug)]
pub(super) struct AnalyticsExportPlan {
    pub(super) path: std::path::PathBuf,
}

impl AnalyticsExportPlan {
    pub(super) fn commit(&self, output: &[u8]) -> Result<()> {
        phantom_core::fs::atomic_write_if_unchanged(&self.path, None, output).with_context(|| {
            format!(
                "Refusing to overwrite analytics export destination {}",
                self.path.display()
            )
        })
    }
}

fn prepare_analytics_export(filename: &str) -> Result<AnalyticsExportPlan> {
    let project_dir = std::env::current_dir().context("Failed to resolve the current project")?;
    prepare_analytics_export_in(&project_dir, filename)
}

pub(super) fn prepare_analytics_export_in(
    project_dir: &std::path::Path,
    filename: &str,
) -> Result<AnalyticsExportPlan> {
    phantom_core::fs::validate_project_filename(filename).context("Invalid --export filename")?;
    let path = project_dir.join(filename);
    if phantom_core::fs::read_regular_file(&path)
        .with_context(|| format!("Refusing unsafe analytics export target {}", path.display()))?
        .is_some()
    {
        anyhow::bail!(
            "Analytics export destination already exists; refusing to overwrite {}",
            path.display()
        );
    }
    Ok(AnalyticsExportPlan { path })
}
