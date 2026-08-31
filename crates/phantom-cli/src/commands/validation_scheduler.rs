//! `phantom validate schedule` and `phantom validate history` sub-commands.
//!
//! `schedule <interval>` — configure the background revalidation scheduler.
//! `schedule --status`   — show current schedule and staleness.
//! `schedule --disable`  — turn off the scheduler.
//! `history`             — display past validation runs.

use anyhow::Result;
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::validation_scheduler::{state_file_path, Schedule, SchedulerState, MAX_HISTORY};

/// Run `phantom validate schedule [interval] [--status] [--disable]`.
pub fn run_schedule(interval: Option<&str>, status: bool, disable: bool, json: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "Not initialized. Run `phantom init` first (no .phantom.toml in {}).",
            project_dir.display()
        );
    }

    let config = PhantomConfig::load(&config_path)?;
    let state_path = state_file_path(config.local_project_id());
    let mut state = SchedulerState::load(&state_path).unwrap_or_default();

    // --disable
    if disable {
        state.schedule = Some(Schedule::Disabled);
        state.save(&state_path)?;
        if json {
            println!("{{\"schedule\":\"disabled\"}}");
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
    state.schedule = Some(sched);
    state.save(&state_path)?;

    if json {
        println!(
            "{{\"schedule\":{:?}}}",
            serde_json::to_string(&state.schedule).unwrap_or_default()
        );
    } else {
        println!(
            "{} Validation schedule set to {}.",
            "ok".green(),
            description.bold()
        );
        println!("  State persisted to: {}", state_path.display());
        println!();
        println!("  To start the background daemon, run `phantom validate schedule --status`");
        println!("  or integrate with a process supervisor (systemd, launchd, etc.).");
    }

    Ok(())
}

/// Run `phantom validate history [--last N] [--json]`.
pub fn run_history(last: Option<usize>, json: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "Not initialized. Run `phantom init` first (no .phantom.toml in {}).",
            project_dir.display()
        );
    }

    let config = PhantomConfig::load(&config_path)?;
    let state_path = state_file_path(config.local_project_id());
    let state = SchedulerState::load(&state_path).unwrap_or_default();

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
    println!(
        "  Showing {} of {} total run(s). Use --last N to see more.",
        entries.len(),
        state.history.len()
    );

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

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
