//! `phantom validate schedule` and `phantom validate history` sub-commands.
//!
//! `schedule <interval>` — configure the background revalidation scheduler.
//! `schedule --status`   — show current schedule and staleness.
//! `schedule --disable`  — turn off the scheduler.
//! `history`             — display past validation runs.

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::validation_scheduler::{state_file_path, Schedule, SchedulerState, MAX_HISTORY};
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Write};

/// Run `phantom validate schedule [interval] [--status] [--disable]`.
pub fn run_schedule(interval: Option<&str>, status: bool, disable: bool, json: bool) -> Result<()> {
    let project_dir = crate::util::project_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");

    let config_before = crate::util::read_config_if_present(&config_path)
        .context("Failed to load .phantom.toml")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Not initialized. Run `phantom init` first (no .phantom.toml in {}).",
                project_dir.display()
            )
        })?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)?;
    let state_path = state_file_path(config.local_project_id());
    let (mut state, before) = SchedulerState::load_exact(&state_path)?;

    // --disable
    if disable {
        require_trusted_terminal_schedule(
            &project_dir,
            config.local_project_id(),
            &config_before,
            &state_path,
            before.as_deref(),
            &Schedule::Disabled,
        )?;
        state.schedule = Some(Schedule::Disabled);
        state.save_if_unchanged(&state_path, before.as_deref())?;
        if json {
            println!("{}", schedule_json(&state.schedule));
        } else {
            println!("{} Validation scheduler disabled.", "info".blue());
        }
        return Ok(());
    }

    // --status (or no args: also show status)
    if status || (interval.is_none() && !disable) {
        return print_schedule_status(&state, json);
    }

    // Set new interval
    let raw = interval.unwrap();
    let sched = Schedule::parse(raw).map_err(|e| anyhow::anyhow!("{}", e))?;

    let description = sched.description();
    require_trusted_terminal_schedule(
        &project_dir,
        config.local_project_id(),
        &config_before,
        &state_path,
        before.as_deref(),
        &sched,
    )?;
    state.schedule = Some(sched);
    state.save_if_unchanged(&state_path, before.as_deref())?;

    if json {
        println!("{}", schedule_json(&state.schedule));
    } else {
        println!(
            "{} Validation schedule set to {}.",
            "ok".green(),
            description.bold()
        );
        println!("  State persisted to: {}", state_path.display());
        println!();
        println!("  Phantom does not run validation on this schedule by itself.");
        println!(
            "  `phantom validate schedule --status` shows when `phantom validate --check-all` last ran."
        );
    }

    Ok(())
}

fn require_trusted_terminal_schedule(
    project_dir: &std::path::Path,
    project_id: &str,
    config_before: &[u8],
    state_path: &std::path::Path,
    state_before: Option<&[u8]>,
    schedule: &Schedule,
) -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!("validation schedule changes require attached stdin, stdout, and stderr terminals; scheduler state was not written");
    }
    let mut digest = Sha256::new();
    digest.update(b"phantom-validation-schedule-v1\0");
    digest.update(config_before);
    if let Some(before) = state_before {
        digest.update(before);
    }
    let challenge = format!(
        "SET VALIDATION SCHEDULE {} IN {} ID {} STATE {} DIGEST {}",
        schedule.description(),
        project_dir.display(),
        project_id,
        state_path.display(),
        hex::encode(digest.finalize())
    );
    eprintln!("This changes persistent validation scheduler policy.\nType this exact challenge to continue:\n{challenge}");
    eprint!("> ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        anyhow::bail!(
            "Schedule confirmation did not match exactly; scheduler state was not written"
        );
    }
    Ok(())
}

/// Run `phantom validate history [--last N] [--json]`.
pub fn run_history(last: Option<usize>, json: bool) -> Result<()> {
    let project_dir = crate::util::project_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");

    let config_before = crate::util::read_config_if_present(&config_path)
        .context("Failed to load .phantom.toml")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Not initialized. Run `phantom init` first (no .phantom.toml in {}).",
                project_dir.display()
            )
        })?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)?;
    let state_path = state_file_path(config.local_project_id());
    let state = SchedulerState::load(&state_path)?;

    if state.history.is_empty() {
        if json {
            println!("[]");
        } else {
            println!(
                "{} No validation history yet. Run `phantom validate --check-all` to start.",
                "info".blue()
            );
        }
        return Ok(());
    }

    let limit = last.unwrap_or(20).min(MAX_HISTORY);
    let entries: Vec<_> = state.history.iter().rev().take(limit).collect();

    if json {
        let out = serde_json::to_string_pretty(&entries)?;
        println!("{out}");
        return Ok(());
    }

    println!("{}", "Validation History".bold().underline());
    println!();

    for record in entries.iter().rev() {
        let ts = format_timestamp(record.started_at);
        let duration = record.finished_at.saturating_sub(record.started_at);

        if let Some(ref err) = record.error {
            println!(
                "  {} {} ({:.1}s)  {}",
                "ERROR".red().bold(),
                ts,
                duration,
                err.dimmed()
            );
        } else {
            let summary = format!(
                "total:{} pass:{} fail:{} unreachable:{}",
                record.total, record.pass, record.fail, record.unreachable
            );
            let status_label = if record.fail > 0 {
                "FAIL ".red().bold().to_string()
            } else if record.unreachable > 0 {
                "WARN ".yellow().bold().to_string()
            } else {
                "pass ".green().to_string()
            };
            println!(
                "  {} {} ({:.1}s)  {}",
                status_label,
                ts,
                duration,
                summary.dimmed()
            );
        }
    }

    println!();
    println!("{}", history_footer(entries.len(), state.history.len()));

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// The `--json` answer after setting or disabling a schedule. `schedule`
/// is the same value `--status --json` reports, not a string holding JSON.
fn schedule_json(schedule: &Option<Schedule>) -> serde_json::Value {
    serde_json::json!({ "schedule": schedule })
}

fn print_schedule_status(state: &SchedulerState, json: bool) -> Result<()> {
    if json {
        let out = serde_json::json!({
            "schedule": state.schedule,
            "last_run_at": state.last_run_at,
            "last_run": state.last_run,
            "stale_1h": state.is_stale(3600),
            "stale_24h": state.is_stale(86400),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("{}", "Validation Scheduler Status".bold().underline());
    println!();

    match &state.schedule {
        None => println!("  Schedule:  {}", "not configured".dimmed()),
        Some(s) => println!("  Schedule:  {}", s.description().bold()),
    }

    if state.last_run_at == 0 {
        println!("  Last run:  {}", "never".yellow());
    } else {
        println!("  Last run:  {}", format_timestamp(state.last_run_at));
        if state.is_stale(86400) {
            println!("  Staleness: {}", "stale (>24h ago)".yellow());
        } else if state.is_stale(3600) {
            println!("  Staleness: {}", "stale (>1h ago)".dimmed());
        } else {
            println!("  Staleness: {}", "fresh".green());
        }
    }

    if let Some(ref run) = state.last_run {
        println!(
            "  Last result: total={} pass={} fail={} unreachable={}",
            run.total, run.pass, run.fail, run.unreachable
        );
    }

    println!("  History:   {} run(s) stored", state.history.len());

    Ok(())
}

fn format_timestamp(ts: u64) -> String {
    // Minimal formatting: show relative time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let age = now.saturating_sub(ts);

    if age < 60 {
        format!("{age}s ago")
    } else if age < 3600 {
        format!("{}m ago", age / 60)
    } else if age < 86400 {
        format!("{}h ago", age / 3600)
    } else {
        format!("{}d ago", age / 86400)
    }
}

/// The line under `validate history`: suggests --last only when runs are
/// hidden.
fn history_footer(shown: usize, total: usize) -> String {
    if shown < total {
        format!("  Showing {shown} of {total} total run(s). Use --last N to see more.")
    } else {
        format!("  Showing all {total} run(s).")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `schedule 6h --json` printed `{"schedule":"{\"interval\":21600}"}`:
    /// the schedule as a string holding JSON, unlike `--status --json`.
    #[test]
    fn set_and_disable_json_report_the_schedule_as_status_does() {
        assert_eq!(
            schedule_json(&Some(Schedule::parse("6h").unwrap())).to_string(),
            r#"{"schedule":{"interval":21600}}"#
        );
        assert_eq!(
            schedule_json(&Some(Schedule::Disabled)).to_string(),
            r#"{"schedule":"disabled"}"#
        );
    }

    #[test]
    fn history_footer_suggests_last_only_when_runs_are_hidden() {
        assert_eq!(history_footer(3, 3), "  Showing all 3 run(s).");
        assert!(history_footer(20, 45).contains("Use --last N to see more."));
    }

    #[test]
    fn headless_schedule_consent_denies_without_write_authority() {
        if !std::io::stdin().is_terminal()
            || !std::io::stdout().is_terminal()
            || !std::io::stderr().is_terminal()
        {
            let error = require_trusted_terminal_schedule(
                std::path::Path::new("/tmp/project"),
                "local-id",
                b"config",
                std::path::Path::new("/tmp/state"),
                None,
                &Schedule::Disabled,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("scheduler state was not written"));
        }
    }
}
