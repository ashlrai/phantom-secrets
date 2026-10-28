use super::*;

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

    let mut reader = open_log_for_follow(&log_path)?;

    if !json_output {
        println!(
            "{}  Tailing {} for anomalies (threshold={:.2}) - Ctrl-C to stop",
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

        // Parse the new event to extract the secret name - skip non-matching.
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

    // This command is read-only. Correlation and incident persistence are an
    // explicit backfill effect guarded by the audit terminal ceremony.
    // The proxy only appends leak events; incidents are persisted by the
    // gated `audit alerts --backfill`. Correlate the same window in memory
    // (nothing written, one audit-log parse) so unpersisted leaks are not
    // reported as all clear.
    let view = engine
        .incident_view(min_confidence)
        .map_err(|e| anyhow::anyhow!("Failed to read leak incidents: {e}"))?;
    let audit_log_present = view.audit_log_present;
    let incidents = view.persisted;
    let uncorrelated = view.uncorrelated;

    if json {
        // One shape whether or not anything was found.
        let out = serde_json::json!({
            "incidents": incidents,
            "uncorrelated_incidents": uncorrelated,
            "provider_credentials_rotated": [],
        });
        let s = serde_json::to_string_pretty(&out)
            .map_err(|e| anyhow::anyhow!("Serialisation error: {e}"))?;
        println!("{}", s);
        return Ok(());
    }

    if incidents.is_empty() && uncorrelated.is_empty() {
        if audit_log_present {
            println!(
                "{}  No persisted active leak incidents (min_confidence={:.2}).",
                "->".blue().bold(),
                min_confidence,
            );
        } else {
            println!(
                "{}  No active leak incidents (min_confidence={:.2}). \
                 No audit log exists: set {} to record leak events.",
                "->".blue().bold(),
                min_confidence,
                "PHANTOM_AUDIT=1".cyan()
            );
        }
        return Ok(());
    }

    println!(
        "{}  {} active leak incident(s) (confidence ≥ {:.2})",
        "->".blue().bold(),
        (incidents.len() + uncorrelated.len())
            .to_string()
            .red()
            .bold(),
        min_confidence,
    );
    if !uncorrelated.is_empty() {
        println!(
            "{}  {} of them are leak events from the last 24 h in the audit log, not persisted yet (status {}). \
             Treat each as a possible leak. Persist them and send configured alerts with {}.",
            "!".yellow().bold(),
            uncorrelated.len().to_string().red().bold(),
            "unpersisted".yellow(),
            "phantom audit alerts --backfill".cyan()
        );
    }
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

    // Unpersisted incidents share the table (same columns, names only).
    let persisted_count = incidents.len();
    for (row, inc) in incidents.iter().chain(uncorrelated.iter()).enumerate() {
        let confidence_str = if inc.confidence >= 0.9 {
            format!("{:.2}", inc.confidence).red().bold().to_string()
        } else {
            format!("{:.2}", inc.confidence).yellow().to_string()
        };

        let status = if row >= persisted_count {
            "unpersisted".yellow().bold().to_string()
        } else if inc.confidence >= 0.9 {
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
        let (config_path, config_before, alerting_config) =
            load_alerting_config_from_project_exact()?;
        let backend_kinds = alerting_config
            .backends
            .iter()
            .map(|backend| match backend {
                phantom_core::leak_correlation::AlertBackendConfig::Webhook { .. } => "webhook",
                phantom_core::leak_correlation::AlertBackendConfig::Slack { .. } => "slack",
                phantom_core::leak_correlation::AlertBackendConfig::PagerDuty { .. } => "pagerduty",
            })
            .collect::<Vec<_>>();
        let backend_origins =
            phantom_core::leak_correlation::alert_backend_review_origins(&alerting_config)
                .context("Alerting configuration contains an unsafe destination")?;
        let config_sha256 = exact_bytes_digest(config_before.as_deref());
        let plan = serde_json::json!({
            "action": "audit-alerts-backfill",
            "project": std::env::current_dir()?.canonicalize().unwrap_or(std::env::current_dir()?),
            "config_path": &config_path,
            "config_sha256": config_sha256,
            "alerting_enabled": alerting_config.enabled,
            "backend_kinds": backend_kinds,
            "backend_origins": backend_origins,
            "alerts_path": &alerts_path,
            "effect": "correlate audit events, dispatch value-free incident metadata to configured backends, and persist alert records",
        });
        require_trusted_terminal_audit_effect(&plan)?;
        recheck_optional_regular_file(&config_path, config_before.as_deref())?;

        // Re-run correlation to pick up any new incidents.
        let engine = LeakCorrelationEngine::new()
            .map_err(|e| anyhow::anyhow!("Cannot initialise leak correlation engine: {e}"))?;
        let incidents = engine
            .run()
            .map_err(|e| anyhow::anyhow!("Correlation engine failed: {e}"))?;

        if !incidents.is_empty() {
            recheck_optional_regular_file(&config_path, config_before.as_deref())?;
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

    let recent = alerter
        .scan_recent_alerts(last)
        .map_err(|e| anyhow::anyhow!("Failed to read alerts: {e}"))?;
    write_alert_list(&mut std::io::stdout().lock(), recent, json)?;
    Ok(())
}

/// Print the listed alerts as JSON or text. The header counts every alert in
/// the file, and the empty state appears only when the file has none.
fn write_alert_list(
    out: &mut dyn Write,
    recent: phantom_core::leak_correlation::RecentAlerts,
    json: bool,
) -> Result<()> {
    let alerts = recent.alerts;

    if recent.total == 0 {
        if json {
            writeln!(out, "[]")?;
        } else {
            writeln!(
                out,
                "{}  No leak alerts found. Run with {} to enable alerting.",
                "->".blue().bold(),
                "`phantom audit alerts --backfill`".cyan()
            )?;
        }
        return Ok(());
    }

    if json {
        let listed = serde_json::to_string_pretty(&alerts)
            .map_err(|e| anyhow::anyhow!("Serialisation error: {e}"))?;
        writeln!(out, "{listed}")?;
        return Ok(());
    }

    writeln!(
        out,
        "{}  {}",
        "->".blue().bold(),
        alerts_header(recent.total, alerts.len())
    )?;
    writeln!(out)?;

    for alert in &alerts {
        let confidence_str = if alert.confidence >= 0.9 {
            format!("{:.2}", alert.confidence).red().bold().to_string()
        } else {
            format!("{:.2}", alert.confidence).yellow().to_string()
        };

        writeln!(
            out,
            "  {}  secret={}  location={}  confidence={}  events={}  backends={}",
            format_unix_ts(alert.alerted_at).dimmed(),
            alert.secret_name.bold(),
            alert.location_label.cyan(),
            confidence_str,
            alert.event_count,
            alert.backends_notified.join(",").dimmed(),
        )?;
        writeln!(
            out,
            "    {}  {}",
            "remediation:".yellow().bold(),
            alert.remediation.dimmed(),
        )?;
        writeln!(out)?;
    }

    Ok(())
}

fn alerts_header(total: usize, shown: usize) -> String {
    format!("{total} leak alert(s) (most recent {shown} shown)")
}

#[cfg(test)]
mod consolidation_tests {
    use super::*;
    #[test]
    fn alert_list_header_counts_every_alert_on_file() {
        use phantom_core::leak_correlation::{LeakAlert, RecentAlerts};
        let alert = |alerted_at: u64| LeakAlert {
            incident_id: format!("incident-{alerted_at}"),
            secret_name: "STRIPE_NAME".to_string(),
            location_label: "body".to_string(),
            confidence: 0.95,
            event_count: 2,
            alerted_at,
            backends_notified: vec!["webhook".to_string()],
            remediation: "rotate it".to_string(),
        };
        let listed = |recent: RecentAlerts| {
            let mut out = Vec::new();
            write_alert_list(&mut out, recent, false).unwrap();
            String::from_utf8(out).unwrap()
        };

        let capped = listed(RecentAlerts {
            alerts: vec![alert(4), alert(5)],
            total: 5,
            unparsable_lines: 0,
        });
        assert!(capped.contains("5 leak alert(s) (most recent 2 shown)"));

        // `--last 0` with alerts on file is not "no alerts".
        let none_listed = listed(RecentAlerts {
            alerts: Vec::new(),
            total: 3,
            unparsable_lines: 0,
        });
        assert!(none_listed.contains("3 leak alert(s) (most recent 0 shown)"));
        assert!(!none_listed.contains("No leak alerts found"));

        assert!(listed(RecentAlerts::default()).contains("No leak alerts found"));
    }
}
