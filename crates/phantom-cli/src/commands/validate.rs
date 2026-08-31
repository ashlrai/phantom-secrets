//! `phantom validate` — live credential health checks.
//!
//! Runs the validation pipeline against all (or selected) secrets in the vault,
//! updating per-secret [`ValidationMetadata`] and printing a compliance report.
//!
//! # Watch mode
//!
//! `phantom validate --watch` runs an infinite polling loop that re-checks each
//! secret according to its per-secret schedule (from `.phantom.toml`) and writes
//! results to `~/.phantom/validation-report.json` for MCP tools to consume.

use anyhow::Result;
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::validator::{
    default_validators, run_validation_pipeline, ValidationMetadata, ValidationReport,
    ValidationStatus,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Default request timeout for each validator HTTP call (one-shot mode).
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Default number of concurrent validation jobs.
const DEFAULT_JOBS: usize = 4;

/// Path to the validation report file written by `--watch`.
pub fn watch_report_path() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".phantom").join("validation-report.json")
}

/// The validation report written to disk by `--watch` (and readable by MCP tools).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchReport {
    /// Unix timestamp when this report was last updated.
    pub updated_at: u64,
    /// The full validation report from the most-recent run.
    pub report: ValidationReport,
    /// Whether any secrets are currently invalid.
    pub has_invalid: bool,
}

/// Run `phantom validate [--check-all] [--watch] [--jobs N] [--json]`.
///
/// - Without `--watch`: runs once, prints a report, exits 1 if any secret is
///   invalid.
/// - With `--watch`: polls indefinitely, honouring per-secret schedules from
///   `.phantom.toml`, writing results to `~/.phantom/validation-report.json`.
pub fn run(check_all: bool, jobs: Option<usize>, json: bool) -> Result<()> {
    run_inner(check_all, jobs, json, false)
}

/// Run `phantom validate --watch`.
pub fn run_watch(jobs: Option<usize>, json: bool) -> Result<()> {
    run_inner(true, jobs, json, true)
}

fn run_inner(check_all: bool, jobs: Option<usize>, json: bool, watch: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "Not initialized. Run `phantom init` first (no .phantom.toml in {}).",
            project_dir.display()
        );
    }

    let config = PhantomConfig::load(&config_path)?;
    let project_id = config.local_project_id().to_string();

    if watch {
        return run_watch_loop(&config, &project_id, jobs, json);
    }

    // One-shot mode.
    let vault = phantom_vault::create_vault(&project_id);
    let names = vault.list()?;

    if names.is_empty() {
        if json {
            println!("{{\"total\":0,\"valid\":0,\"invalid\":0,\"unreachable\":0,\"not_checked\":0,\"entries\":[]}}");
        } else {
            println!("{} No secrets in vault to validate.", "info".blue());
        }
        return Ok(());
    }

    if !check_all {
        anyhow::bail!(
            "Specify --check-all to validate all secrets, or use `phantom validate --check-all`."
        );
    }

    let n_jobs = jobs.unwrap_or(DEFAULT_JOBS);
    let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);

    // Collect secrets, apply per-secret timeout override where configured.
    // For one-shot mode, we use the global default timeout but respect the
    // per-secret validation config's timeout_secs when building the pipeline.
    let mut secrets: Vec<(String, zeroize::Zeroizing<String>)> = Vec::new();
    for name in &names {
        let value = vault.retrieve(name)?;
        secrets.push((
            name.clone(),
            zeroize::Zeroizing::new(String::from(value.as_str())),
        ));
    }

    if !json {
        println!(
            "{} Validating {} secret(s) with {} job(s)…",
            "info".blue(),
            secrets.len(),
            n_jobs
        );
    }

    let validators = default_validators();
    let report = run_validation_pipeline(secrets, &validators, n_jobs, timeout);

    // Persist ValidationMetadata for each entry back into the vault.
    for entry in &report.entries {
        let meta = match entry.status {
            ValidationStatus::Valid => ValidationMetadata::mark_valid(&entry.validator),
            ValidationStatus::Invalid => ValidationMetadata::mark_invalid(
                &entry.validator,
                entry.reason.as_deref().unwrap_or("unknown"),
            ),
            ValidationStatus::Unreachable => ValidationMetadata::mark_unreachable(
                &entry.validator,
                entry.reason.as_deref().unwrap_or("network error"),
            ),
            ValidationStatus::NotChecked | ValidationStatus::Skipped => continue,
        };
        // Best-effort — ignore errors (keychain vault may not support metadata).
        let _ = vault.set_validation_metadata(&entry.name, meta);
    }

    if json {
        let out = serde_json::to_string_pretty(&report)?;
        println!("{out}");
        // Exit 1 if any invalid secrets.
        if report.invalid > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    print_report_human(&report);

    if report.invalid > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Watch-mode: poll per-secret schedules in an infinite loop.
///
/// Each secret's re-check interval comes from
/// `[phantom.secrets.{name}.validation]` in `.phantom.toml`.  When no
/// per-secret config exists, the default (`daily`) is used.
fn run_watch_loop(
    config: &PhantomConfig,
    project_id: &str,
    jobs: Option<usize>,
    json: bool,
) -> Result<()> {
    let report_path = watch_report_path();
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let n_jobs = jobs.unwrap_or(DEFAULT_JOBS);

    if !json {
        println!(
            "{} Validation watch mode started. Writing results to {}",
            "info".blue(),
            report_path.display()
        );
        println!("  Press Ctrl+C to stop.");
    }

    // Poll every 60 seconds; each secret is only re-validated when its own
    // schedule says it is due.
    let poll_interval = Duration::from_secs(60);

    loop {
        let vault = phantom_vault::create_vault(project_id);
        let names = match vault.list() {
            Ok(n) => n,
            Err(e) => {
                if !json {
                    eprintln!("{} vault list failed: {e}", "warn".yellow());
                }
                std::thread::sleep(poll_interval);
                continue;
            }
        };

        // Determine which secrets are due for a re-check.
        let mut due_secrets: Vec<(String, zeroize::Zeroizing<String>)> = Vec::new();

        for name in &names {
            // Load the per-secret validation config (or use defaults).
            let val_cfg = config
                .phantom
                .secrets
                .get(name)
                .and_then(|ov| ov.validation.clone())
                .unwrap_or_default();

            // Load the last check timestamp from vault metadata.
            let last_check_ts = vault
                .get_validation_metadata(name)
                .unwrap_or_default()
                .last_check_ts;

            if val_cfg.is_due(last_check_ts) {
                match vault.retrieve(name) {
                    Ok(value) => {
                        due_secrets.push((
                            name.clone(),
                            zeroize::Zeroizing::new(String::from(value.as_str())),
                        ));
                    }
                    Err(e) => {
                        if !json {
                            eprintln!("{} could not retrieve {name}: {e}", "warn".yellow());
                        }
                    }
                }
            }
        }

        if !due_secrets.is_empty() {
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Compute per-secret timeout — use max of all due secrets' configs.
            let timeout_secs = due_secrets
                .iter()
                .filter_map(|(name, _)| {
                    config
                        .phantom
                        .secrets
                        .get(name)
                        .and_then(|ov| ov.validation.as_ref())
                        .map(|v| v.timeout_secs)
                })
                .max()
                .unwrap_or(30);

            let timeout = Duration::from_secs(timeout_secs);
            let validators = default_validators();
            let report = run_validation_pipeline(due_secrets, &validators, n_jobs, timeout);

            // Persist ValidationMetadata for each entry back into the vault.
            for entry in &report.entries {
                let meta = match entry.status {
                    ValidationStatus::Valid => ValidationMetadata::mark_valid(&entry.validator),
                    ValidationStatus::Invalid => ValidationMetadata::mark_invalid(
                        &entry.validator,
                        entry.reason.as_deref().unwrap_or("unknown"),
                    ),
                    ValidationStatus::Unreachable => ValidationMetadata::mark_unreachable(
                        &entry.validator,
                        entry.reason.as_deref().unwrap_or("network error"),
                    ),
                    ValidationStatus::NotChecked | ValidationStatus::Skipped => continue,
                };
                let _ = vault.set_validation_metadata(&entry.name, meta);
            }

            // Write report to disk for MCP tools.
            let watch_report = WatchReport {
                updated_at: now_ts,
                has_invalid: report.invalid > 0,
                report,
            };

            if let Ok(json_bytes) = serde_json::to_vec_pretty(&watch_report) {
                let _ = phantom_core::fs::atomic_write(&report_path, &json_bytes);
            }

            if !json {
                println!(
                    "{} [{}] Validated {} secret(s) — valid:{} invalid:{} unreachable:{}",
                    "ok".green(),
                    format_now(),
                    watch_report.report.total,
                    watch_report.report.valid,
                    watch_report.report.invalid,
                    watch_report.report.unreachable,
                );
            }
        }

        std::thread::sleep(poll_interval);
    }
}

// ── Human-readable report printer ────────────────────────────────────────────

fn print_report_human(report: &ValidationReport) {
    println!();
    println!("{}", "Validation Report".bold().underline());
    println!();

    for entry in &report.entries {
        let status_str = match entry.status {
            ValidationStatus::Valid => "  valid      ".green().to_string(),
            ValidationStatus::Invalid => "  INVALID    ".red().bold().to_string(),
            ValidationStatus::Unreachable => "  unreachable".yellow().to_string(),
            ValidationStatus::NotChecked => "  not_checked".dimmed().to_string(),
            ValidationStatus::Skipped => "  skipped    ".dimmed().to_string(),
        };

        let reason = entry
            .reason
            .as_deref()
            .map(|r| format!(" — {r}"))
            .unwrap_or_default();

        println!(
            "{} {} (validator: {}{})",
            status_str,
            entry.name.bold(),
            entry.validator.dimmed(),
            reason
        );
    }

    println!();
    println!(
        "  Total: {}  Valid: {}  {}  {}  Not checked: {}",
        report.total,
        report.valid.to_string().green(),
        format!("Invalid: {}", report.invalid).red(),
        format!("Unreachable: {}", report.unreachable).yellow(),
        report.not_checked
    );

    if report.invalid > 0 {
        println!();
        println!(
            "  {} {} credential(s) are INVALID — rotate them immediately with `phantom rotate`.",
            "!".red().bold(),
            report.invalid
        );
    }

    if report.unreachable > 0 {
        println!(
            "  {} {} credential(s) could not be reached — check network connectivity.",
            "?".yellow().bold(),
            report.unreachable
        );
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn format_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple relative formatting — good enough for a watch-mode status line.
    format!("t={secs}")
}
