//! `phantom validate` — live credential health checks.
//!
//! Runs the validation pipeline against all (or selected) secrets in the vault,
//! updating per-secret [`ValidationMetadata`] and printing a compliance report.

use anyhow::Result;
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::validator::{
    default_validators, run_validation_pipeline, ValidationStatus,
};
use std::time::Duration;

/// Default request timeout for each validator HTTP call.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Default number of concurrent validation jobs.
const DEFAULT_JOBS: usize = 4;

/// Run `phantom validate --check-all [--async] [--jobs N]`.
///
/// - Loads the vault for the current project.
/// - Retrieves each secret value (Zeroizing).
/// - Runs the validator pipeline.
/// - Prints the compliance report.
pub fn run(check_all: bool, jobs: Option<usize>, json: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "Not initialized. Run `phantom init` first (no .phantom.toml in {}).",
            project_dir.display()
        );
    }

    let config = PhantomConfig::load(&config_path)?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

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

    // Retrieve all secret values for validation (zeroized after use).
    let mut secrets: Vec<(String, zeroize::Zeroizing<String>)> = Vec::new();
    for name in &names {
        let value = vault.retrieve(name)?;
        secrets.push((name.clone(), zeroize::Zeroizing::new(String::from(value.as_str()))));
    }

    let n_jobs = jobs.unwrap_or(DEFAULT_JOBS);
    let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);
    let validators = default_validators();

    if !json {
        println!(
            "{} Validating {} secret(s) with {} job(s)…",
            "info".blue(),
            secrets.len(),
            n_jobs
        );
    }

    let report = run_validation_pipeline(secrets, &validators, n_jobs, timeout);

    if json {
        let out = serde_json::to_string_pretty(&report)?;
        println!("{out}");
        return Ok(());
    }

    // Human-readable output
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

    Ok(())
}
