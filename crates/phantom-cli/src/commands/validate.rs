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
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
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
    let project_dir = std::env::current_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "Not initialized. Run `phantom init` first (no .phantom.toml in {}).",
            project_dir.display()
        );
    }

    let config_before = phantom_core::fs::read_regular_file(&config_path)?
        .ok_or_else(|| anyhow::anyhow!("Project is not initialized"))?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)?;
    let project_id = config.local_project_id().to_string();

    if watch {
        return run_watch_loop(
            &project_dir,
            &config_path,
            &config_before,
            &config,
            &project_id,
            jobs,
            json,
        );
    }

    // One-shot mode.
    let vault = phantom_vault::try_create_vault(&project_id)?;
    let mut names = vault.list()?;
    names.sort();
    validate_consent_names(&names)?;

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

    let n_jobs = jobs.unwrap_or(DEFAULT_JOBS).clamp(1, 16);
    let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);
    let metadata_before = snapshot_validation_metadata(vault.as_ref(), &names)?;
    require_trusted_terminal_validation(
        &project_dir,
        &project_id,
        &config_before,
        &names,
        n_jobs,
        timeout.as_secs(),
        false,
    )?;

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

    persist_validation_metadata(vault.as_ref(), &report, &metadata_before)?;

    if json {
        let out = serde_json::to_string_pretty(&report)?;
        println!("{out}");
        // Exit 1 if any invalid secrets.
        if report.invalid > 0 {
            anyhow::bail!("one or more credentials were reported invalid");
        }
        return Ok(());
    }

    print_report_human(&report);

    if report.invalid > 0 {
        anyhow::bail!("one or more credentials were reported invalid");
    }
    Ok(())
}

/// Watch-mode: poll per-secret schedules in an infinite loop.
///
/// Each secret's re-check interval comes from
/// `[phantom.secrets.{name}.validation]` in `.phantom.toml`.  When no
/// per-secret config exists, the default (`daily`) is used.
fn run_watch_loop(
    project_dir: &std::path::Path,
    config_path: &std::path::Path,
    config_before: &[u8],
    config: &PhantomConfig,
    project_id: &str,
    jobs: Option<usize>,
    json: bool,
) -> Result<()> {
    let report_path = watch_report_path();
    let n_jobs = jobs.unwrap_or(DEFAULT_JOBS).clamp(1, 16);
    let initial_vault = phantom_vault::try_create_vault(project_id)?;
    let mut authorized_names = initial_vault.list()?;
    authorized_names.sort();
    validate_consent_names(&authorized_names)?;
    let watch_timeout_secs = authorized_names
        .iter()
        .filter_map(|name| {
            config
                .phantom
                .secrets
                .get(name)
                .and_then(|override_config| override_config.validation.as_ref())
                .map(|validation| validation.timeout_secs)
        })
        .max()
        .unwrap_or(30);
    require_trusted_terminal_validation(
        project_dir,
        project_id,
        config_before,
        &authorized_names,
        n_jobs,
        watch_timeout_secs,
        true,
    )?;
    phantom_core::fs::ensure_real_parent(&report_path)?;

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
        if phantom_core::fs::read_regular_file(config_path)?.as_deref() != Some(config_before) {
            anyhow::bail!(
                "Validation watch authorization ended because .phantom.toml changed; restart and reauthorize"
            );
        }
        let vault = phantom_vault::try_create_vault(project_id)?;
        let mut names = match vault.list() {
            Ok(n) => n,
            Err(e) => {
                if !json {
                    eprintln!("{} vault list failed: {e}", "warn".yellow());
                }
                std::thread::sleep(poll_interval);
                continue;
            }
        };
        names.sort();
        if names != authorized_names {
            anyhow::bail!(
                "Validation watch authorization ended because the vault name set changed; restart and reauthorize"
            );
        }

        // Determine which secrets are due for a re-check.
        let mut due_names = Vec::new();

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
                due_names.push(name.clone());
            }
        }

        if !due_names.is_empty() {
            let metadata_before = snapshot_validation_metadata(vault.as_ref(), &due_names)?;
            let mut due_secrets: Vec<(String, zeroize::Zeroizing<String>)> = Vec::new();
            for name in &due_names {
                let value = vault.retrieve(name)?;
                due_secrets.push((name.clone(), value));
            }
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let timeout = Duration::from_secs(watch_timeout_secs);
            let validators = default_validators();
            let report = run_validation_pipeline(due_secrets, &validators, n_jobs, timeout);

            if let Err(error) =
                persist_validation_metadata(vault.as_ref(), &report, &metadata_before)
            {
                eprintln!(
                    "{} validation results were computed but metadata did not commit atomically: {error}",
                    "error".red().bold()
                );
                std::thread::sleep(poll_interval);
                continue;
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

fn persist_validation_metadata(
    vault: &dyn phantom_vault::VaultBackend,
    report: &ValidationReport,
    expected_before: &BTreeMap<String, Option<ValidationMetadata>>,
) -> Result<()> {
    let mut changes = Vec::new();
    for entry in &report.entries {
        let replacement = match entry.status {
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
        changes.push(phantom_vault::ValidationMetadataCas {
            name: entry.name.clone(),
            expected: expected_before
                .get(&entry.name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing validation metadata before-image"))?,
            replacement: Some(replacement),
        });
    }
    if changes.is_empty() {
        return Ok(());
    }
    if vault.compare_and_swap_validation_metadata_batch(&changes)? {
        Ok(())
    } else {
        anyhow::bail!(
            "validation metadata changed concurrently; no validation metadata was committed"
        )
    }
}

fn snapshot_validation_metadata(
    vault: &dyn phantom_vault::VaultBackend,
    names: &[String],
) -> Result<BTreeMap<String, Option<ValidationMetadata>>> {
    names
        .iter()
        .map(|name| Ok((name.clone(), vault.get_validation_metadata_exact(name)?)))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn require_trusted_terminal_validation(
    project_dir: &std::path::Path,
    project_id: &str,
    config_before: &[u8],
    names: &[String],
    jobs: usize,
    timeout_secs: u64,
    watch: bool,
) -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "live validation requires attached stdin, stdout, and stderr terminals; no credential was retrieved and no provider request was made"
        );
    }
    let mut digest = Sha256::new();
    digest.update(b"phantom-validation-authority-v1\0");
    digest.update(config_before);
    for name in names {
        digest.update(b"\0");
        digest.update(name.as_bytes());
    }
    digest.update(jobs.to_le_bytes());
    digest.update(timeout_secs.to_le_bytes());
    digest.update([u8::from(watch)]);
    let digest = hex::encode(digest.finalize());
    let mode = if watch { "WATCH" } else { "ONCE" };
    let challenge = format!(
        "VALIDATE {mode} {} SECRETS IN {} ID {} JOBS {} TIMEOUT {} DIGEST {}",
        names.len(),
        project_dir.display(),
        project_id,
        jobs,
        timeout_secs,
        digest
    );
    eprintln!(
        "Live validation sends each selected credential to its configured provider.{}\nSelected name count: {}\nType this exact challenge to continue:\n{}",
        if watch {
            " This authorizes ongoing scheduled access until terminated; config or name drift ends authorization."
        } else {
            ""
        },
        names.len(),
        challenge
    );
    eprint!("> ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        anyhow::bail!(
            "validation confirmation did not match exactly; no credential was retrieved and no provider request was made"
        );
    }
    Ok(())
}

fn validate_consent_names(names: &[String]) -> Result<()> {
    const MAX_NAMES: usize = 4096;
    const MAX_NAME_BYTES: usize = 128;
    const MAX_TOTAL_BYTES: usize = MAX_NAMES * MAX_NAME_BYTES;
    if names.len() > MAX_NAMES || names.iter().map(String::len).sum::<usize>() > MAX_TOTAL_BYTES {
        anyhow::bail!("validation name set is too large to authorize safely");
    }
    for name in names {
        let mut bytes = name.bytes();
        if name.is_empty()
            || name.len() > MAX_NAME_BYTES
            || !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            anyhow::bail!(
                "vault contains a name that cannot be represented safely in validation authority"
            );
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::validator::ValidationEntry;
    use phantom_vault::file::FileVault;
    use phantom_vault::VaultBackend;

    #[test]
    fn stale_validation_before_image_commits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FileVault::new(
            &crate::test_support::canonical_tempdir_path(&dir),
            "validate-cas",
            "passphrase".into(),
        )
        .unwrap();
        vault.store("A", "secret").unwrap();
        vault.store("B", "secret").unwrap();
        let expected = snapshot_validation_metadata(&vault, &["A".into(), "B".into()]).unwrap();
        let concurrent = ValidationMetadata::mark_unreachable("owner", "newer result");
        vault
            .set_validation_metadata("B", concurrent.clone())
            .unwrap();
        let report = ValidationReport {
            generated_at: 1,
            total: 2,
            valid: 2,
            invalid: 0,
            unreachable: 0,
            not_checked: 0,
            entries: vec![
                ValidationEntry {
                    name: "A".into(),
                    validator: "test".into(),
                    status: ValidationStatus::Valid,
                    reason: None,
                    checked_at: 1,
                },
                ValidationEntry {
                    name: "B".into(),
                    validator: "test".into(),
                    status: ValidationStatus::Valid,
                    reason: None,
                    checked_at: 1,
                },
            ],
        };
        assert!(persist_validation_metadata(&vault, &report, &expected).is_err());
        assert_eq!(vault.get_validation_metadata_exact("A").unwrap(), None);
        assert_eq!(
            vault.get_validation_metadata_exact("B").unwrap(),
            Some(concurrent)
        );
    }

    #[test]
    fn headless_validation_authority_fails_before_effects() {
        if !std::io::stdin().is_terminal()
            || !std::io::stdout().is_terminal()
            || !std::io::stderr().is_terminal()
        {
            let error = require_trusted_terminal_validation(
                std::path::Path::new("/tmp/project"),
                "local-id",
                b"config",
                &["A".into()],
                1,
                10,
                false,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("no credential was retrieved"));
        }
    }

    #[test]
    fn validation_authority_rejects_control_names_and_oversized_sets() {
        assert!(validate_consent_names(&["SAFE\nSPOOF".into()]).is_err());
        assert!(validate_consent_names(&["A".repeat(129)]).is_err());
        assert!(validate_consent_names(&vec!["A".into(); 4097]).is_err());
    }
}
