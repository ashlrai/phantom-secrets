use super::*;

/// `phantom audit export-range` - export audit rows with date-range + field filters.
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
    use phantom_core::audit_export::{parse_date_range, AuditExporter, ExportFilter};

    if !matches!(format, "csv" | "json") {
        return Err(anyhow::anyhow!(
            "Invalid format '{}'. Use: csv or json",
            format
        ));
    }
    let (from_ts, to_ts) = parse_date_range(from, to).map_err(anyhow::Error::msg)?;

    let exporter =
        AuditExporter::new().map_err(|e| anyhow::anyhow!("Failed to initialise exporter: {e}"))?;

    let filter = ExportFilter {
        from_ts,
        to_ts,
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
    }
    print!("{}", render_export_range(format, &rows)?);

    Ok(())
}

/// The exact stdout of `phantom audit export-range`. An empty match stays
/// machine-readable, like `phantom audit export`: JSON is an empty array, so
/// `| jq` sees valid input instead of nothing. CSV keeps the empty-stdout
/// behavior `phantom audit export` has for no records.
pub(super) fn render_export_range(
    format: &str,
    rows: &[phantom_core::audit_export::AuditExportRow],
) -> Result<String> {
    use phantom_core::audit_export::AuditExporter;
    match format {
        "csv" if rows.is_empty() => Ok(String::new()),
        "csv" => Ok(AuditExporter::rows_to_csv(rows)),
        "json" => {
            let json = AuditExporter::rows_to_json(rows)
                .map_err(|e| anyhow::anyhow!("Serialisation error: {e}"))?;
            Ok(format!("{json}\n"))
        }
        other => Err(anyhow::anyhow!(
            "Invalid format '{other}'. Use: csv or json"
        )),
    }
}

/// `phantom audit report --type compliance` - generate and optionally save a
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
    use phantom_core::audit_export::{parse_date_range, AuditExporter};

    if report_type != "compliance" {
        return Err(anyhow::anyhow!(
            "Unknown report type '{}'. Supported: compliance",
            report_type
        ));
    }

    let (from_ts, to_ts) = parse_date_range(from, to).map_err(anyhow::Error::msg)?;

    let exporter =
        AuditExporter::new().map_err(|e| anyhow::anyhow!("Failed to initialise exporter: {e}"))?;

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
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(std::path::PathBuf::from)
            .map_err(|_| anyhow::anyhow!("Cannot resolve home directory"))?;
        let plan = serde_json::json!({
            "action": "audit-report-save",
            "report_type": report_type,
            "from": from,
            "to": to,
            "compact_stdout": compact,
            "reports_directory": home.join(".phantom").join("reports"),
            "effect": "create one new local compliance report; never overwrite and never perform network I/O",
        });
        require_trusted_terminal_audit_effect(&plan)?;
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
