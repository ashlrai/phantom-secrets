//! Automated Secret Revalidation Scheduler
//!
//! Provides a background scheduler that periodically invokes the validation
//! pipeline and persists run history to `.phantom/validation-state.json`.
//!
//! # Schedule formats
//!
//! | String         | Interval        |
//! |----------------|-----------------|
//! | `"hourly"`     | 1 h             |
//! | `"6h"`         | 6 h             |
//! | `"daily"`      | 24 h            |
//! | `"daily@2am"`  | 24 h (hint: 2 AM) |
//! | `"weekly"`     | 7 × 24 h        |
//! | `"disabled"`   | scheduler off   |
//!
//! The daemon task runs inside a `tokio` runtime. After each tick it writes a
//! [`SchedulerState`] record to `.phantom/validation-state.json` via an atomic
//! write so the file is never half-written on a crash.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Schedule ─────────────────────────────────────────────────────────────────

/// A parsed validation schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Schedule {
    /// Run every N seconds.
    Interval(u64),
    /// Scheduler is explicitly disabled.
    Disabled,
}

impl Schedule {
    /// Parse a human-readable schedule string.
    ///
    /// Accepted formats: `"hourly"`, `"6h"`, `"30m"`, `"daily"`,
    /// `"daily@<HH>am"` / `"daily@<HH>pm"`, `"weekly"`, `"disabled"`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let lower = s.trim().to_lowercase();
        match lower.as_str() {
            "disabled" | "off" | "none" => return Ok(Schedule::Disabled),
            "hourly" => return Ok(Schedule::Interval(3600)),
            "daily" => return Ok(Schedule::Interval(86400)),
            "weekly" => return Ok(Schedule::Interval(7 * 86400)),
            _ => {}
        }

        // daily@<N>am / daily@<N>pm  — we treat this as a 24-hour cycle;
        // the optional AM/PM suffix is accepted but we don't implement
        // wall-clock alignment (that would require a full scheduler).
        if lower.starts_with("daily@") {
            return Ok(Schedule::Interval(86400));
        }

        // e.g. "6h", "12h", "2h"
        if let Some(hours) = lower.strip_suffix('h') {
            let n: u64 = hours
                .parse()
                .map_err(|_| format!("invalid hours value in schedule '{s}'"))?;
            if n == 0 {
                return Err("schedule interval must be > 0".to_string());
            }
            return Ok(Schedule::Interval(n * 3600));
        }

        // e.g. "30m", "90m"
        if let Some(mins) = lower.strip_suffix('m') {
            let n: u64 = mins
                .parse()
                .map_err(|_| format!("invalid minutes value in schedule '{s}'"))?;
            if n == 0 {
                return Err("schedule interval must be > 0".to_string());
            }
            return Ok(Schedule::Interval(n * 60));
        }

        // e.g. bare integer seconds (useful in tests)
        if let Ok(secs) = lower.parse::<u64>() {
            if secs == 0 {
                return Err("schedule interval must be > 0".to_string());
            }
            return Ok(Schedule::Interval(secs));
        }

        Err(format!(
            "unrecognized schedule '{s}'. Use: hourly, 6h, daily, daily@2am, weekly, disabled"
        ))
    }

    /// Return the interval duration, or `None` if disabled.
    pub fn interval(&self) -> Option<Duration> {
        match self {
            Schedule::Interval(secs) => Some(Duration::from_secs(*secs)),
            Schedule::Disabled => None,
        }
    }

    /// Return a human-readable description.
    pub fn description(&self) -> String {
        match self {
            Schedule::Interval(secs) => {
                if *secs % (7 * 86400) == 0 {
                    format!("every {} week(s)", secs / (7 * 86400))
                } else if *secs % 86400 == 0 {
                    format!("every {} day(s)", secs / 86400)
                } else if *secs % 3600 == 0 {
                    format!("every {} hour(s)", secs / 3600)
                } else if *secs % 60 == 0 {
                    format!("every {} minute(s)", secs / 60)
                } else {
                    format!("every {secs}s")
                }
            }
            Schedule::Disabled => "disabled".to_string(),
        }
    }
}

impl std::fmt::Display for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ── Per-run history entry ─────────────────────────────────────────────────────

/// Summary of a single scheduler-triggered validation run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationRunRecord {
    /// Unix timestamp when the run started.
    pub started_at: u64,
    /// Unix timestamp when the run finished.
    pub finished_at: u64,
    /// Total secrets checked.
    pub total: usize,
    /// Secrets confirmed valid.
    pub pass: usize,
    /// Secrets confirmed invalid (rotate immediately).
    pub fail: usize,
    /// Secrets that could not be reached.
    pub unreachable: usize,
    /// Secrets with no applicable validator.
    pub not_checked: usize,
    /// Error message if the run itself failed (e.g., vault unreadable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ValidationRunRecord {
    /// Build a record from a completed [`crate::validator::ValidationReport`].
    pub fn from_report(started_at: u64, report: &crate::validator::ValidationReport) -> Self {
        Self {
            started_at,
            finished_at: now_secs(),
            total: report.total,
            pass: report.valid,
            fail: report.invalid,
            unreachable: report.unreachable,
            not_checked: report.not_checked,
            error: None,
        }
    }

    /// Build an error record when the run itself failed.
    pub fn error_record(started_at: u64, err: impl Into<String>) -> Self {
        Self {
            started_at,
            finished_at: now_secs(),
            total: 0,
            pass: 0,
            fail: 0,
            unreachable: 0,
            not_checked: 0,
            error: Some(err.into()),
        }
    }
}

// ── Persistent state ──────────────────────────────────────────────────────────

/// The contents of `.phantom/validation-state.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SchedulerState {
    /// The currently active schedule.
    pub schedule: Option<Schedule>,
    /// Unix timestamp of the last successful validation run (0 = never).
    #[serde(default)]
    pub last_run_at: u64,
    /// Summary of the last run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run: Option<ValidationRunRecord>,
    /// History of past runs (newest last, capped at [`MAX_HISTORY`]).
    #[serde(default)]
    pub history: Vec<ValidationRunRecord>,
}

/// Maximum number of history entries retained.
pub const MAX_HISTORY: usize = 100;

impl SchedulerState {
    /// Load state from `path`, returning a default if the file doesn't exist.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        let state: Self = serde_json::from_str(&raw)?;
        Ok(state)
    }

    /// Persist state to `path` using an atomic write.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        crate::fs::atomic_write(path, &json)?;
        Ok(())
    }

    /// Append a run record, evicting the oldest entry if over [`MAX_HISTORY`].
    pub fn push_run(&mut self, record: ValidationRunRecord) {
        self.last_run_at = record.finished_at;
        self.last_run = Some(record.clone());
        self.history.push(record);
        if self.history.len() > MAX_HISTORY {
            let drain_count = self.history.len() - MAX_HISTORY;
            self.history.drain(..drain_count);
        }
    }

    /// Returns true if validation is considered stale: never run, or last run
    /// older than `threshold_secs`.
    pub fn is_stale(&self, threshold_secs: u64) -> bool {
        if self.last_run_at == 0 {
            return true;
        }
        now_secs().saturating_sub(self.last_run_at) > threshold_secs
    }

    /// Returns the number of seconds until the next scheduled run, or `None`
    /// if there is no schedule or next run is overdue.
    pub fn secs_until_next_run(&self) -> Option<u64> {
        let interval = self.schedule.as_ref()?.interval()?;
        let elapsed = now_secs().saturating_sub(self.last_run_at);
        let interval_secs = interval.as_secs();
        if elapsed >= interval_secs {
            None // overdue
        } else {
            Some(interval_secs - elapsed)
        }
    }
}

// ── State file path helper ────────────────────────────────────────────────────

/// Return the path to the validation state file for the given project ID.
///
/// The file lives at `~/.phantom/<project_id>/validation-state.json`, which
/// mirrors the layout used by the vault and shadow-store.
pub fn state_file_path(project_id: &str) -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".phantom")
        .join(project_id)
        .join("validation-state.json")
}

// ── Daemon task ───────────────────────────────────────────────────────────────

/// Token returned by [`spawn_scheduler`] that cancels the background task when
/// dropped.
pub struct SchedulerHandle {
    cancel: tokio::sync::oneshot::Sender<()>,
}

impl SchedulerHandle {
    /// Stop the background scheduler.
    pub fn stop(self) {
        let _ = self.cancel.send(());
    }
}

/// A function that performs one validation tick and returns a [`ValidationRunRecord`].
///
/// The implementation lives in `phantom-cli` (which can depend on `phantom-vault`);
/// `phantom-core` only holds the scheduling logic and state persistence.
pub type TickFn = Box<dyn Fn(u64) -> ValidationRunRecord + Send + Sync + 'static>;

/// Configuration for a scheduler daemon.
pub struct SchedulerConfig {
    /// Validation interval.
    pub schedule: Schedule,
    /// Project ID (for state file path).
    pub project_id: String,
    /// Callback that performs one validation tick, receiving `started_at` (Unix
    /// timestamp) and returning the completed [`ValidationRunRecord`].
    ///
    /// The implementation is supplied by the CLI layer so that `phantom-core`
    /// does not need to depend on `phantom-vault`.
    pub tick_fn: TickFn,
}

/// Spawn a background tokio task that runs the validation pipeline on the
/// given [`SchedulerConfig::schedule`].
///
/// Returns a [`SchedulerHandle`] — drop it (or call `.stop()`) to cancel.
///
/// # Panics
/// Panics if called outside a tokio runtime.
pub fn spawn_scheduler(config: SchedulerConfig) -> anyhow::Result<SchedulerHandle> {
    let interval_secs = match config.schedule.interval() {
        Some(d) => d.as_secs(),
        None => anyhow::bail!("cannot spawn scheduler for a disabled schedule"),
    };

    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    let project_id = config.project_id.clone();
    // Wrap in Arc so we can share ownership with the spawned task.
    let tick_fn = std::sync::Arc::new(config.tick_fn);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        // The first tick fires immediately; subsequent ticks respect the interval.
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // Clone the Arc (cheap) and project_id for this tick.
                    let pid = project_id.clone();
                    let tf = tick_fn.clone();
                    tokio::task::spawn_blocking(move || {
                        run_one_tick_sync(&pid, &tf);
                    }).await.unwrap_or_else(|e| {
                        tracing::warn!("validation scheduler: tick task panicked: {e}");
                    });
                }
                _ = &mut rx => {
                    break;
                }
            }
        }
    });

    Ok(SchedulerHandle { cancel: tx })
}

/// Execute one tick synchronously: call the tick_fn, then persist state.
fn run_one_tick_sync(project_id: &str, tick_fn: &TickFn) {
    let started_at = now_secs();
    let state_path = state_file_path(project_id);

    // Load existing state (ignore load error — we'll write a fresh one).
    let mut state = SchedulerState::load(&state_path).unwrap_or_default();

    // Run the validation synchronously via the injected callback.
    let record = tick_fn(started_at);
    state.push_run(record);

    // Best-effort persist; log but don't crash on failure.
    if let Err(e) = state.save(&state_path) {
        tracing::warn!("validation scheduler: failed to persist state: {e}");
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Schedule parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_hourly() {
        assert_eq!(Schedule::parse("hourly").unwrap(), Schedule::Interval(3600));
    }

    #[test]
    fn parse_daily() {
        assert_eq!(Schedule::parse("daily").unwrap(), Schedule::Interval(86400));
    }

    #[test]
    fn parse_weekly() {
        assert_eq!(
            Schedule::parse("weekly").unwrap(),
            Schedule::Interval(7 * 86400)
        );
    }

    #[test]
    fn parse_daily_at_2am() {
        // daily@Xam/pm is parsed as a 24-hour cycle
        assert_eq!(
            Schedule::parse("daily@2am").unwrap(),
            Schedule::Interval(86400)
        );
    }

    #[test]
    fn parse_6h() {
        assert_eq!(Schedule::parse("6h").unwrap(), Schedule::Interval(6 * 3600));
    }

    #[test]
    fn parse_12h() {
        assert_eq!(
            Schedule::parse("12h").unwrap(),
            Schedule::Interval(12 * 3600)
        );
    }

    #[test]
    fn parse_30m() {
        assert_eq!(Schedule::parse("30m").unwrap(), Schedule::Interval(30 * 60));
    }

    #[test]
    fn parse_disabled() {
        assert_eq!(Schedule::parse("disabled").unwrap(), Schedule::Disabled);
        assert_eq!(Schedule::parse("off").unwrap(), Schedule::Disabled);
        assert_eq!(Schedule::parse("none").unwrap(), Schedule::Disabled);
    }

    #[test]
    fn parse_bare_seconds() {
        assert_eq!(Schedule::parse("120").unwrap(), Schedule::Interval(120));
    }

    #[test]
    fn parse_unknown_returns_err() {
        assert!(Schedule::parse("bogus-schedule").is_err());
    }

    #[test]
    fn parse_zero_h_returns_err() {
        assert!(Schedule::parse("0h").is_err());
    }

    #[test]
    fn parse_zero_m_returns_err() {
        assert!(Schedule::parse("0m").is_err());
    }

    #[test]
    fn interval_disabled_returns_none() {
        assert_eq!(Schedule::Disabled.interval(), None);
    }

    #[test]
    fn interval_returns_duration() {
        assert_eq!(
            Schedule::Interval(3600).interval(),
            Some(Duration::from_secs(3600))
        );
    }

    // ── Schedule display ─────────────────────────────────────────────────

    #[test]
    fn description_hourly() {
        assert_eq!(Schedule::Interval(3600).description(), "every 1 hour(s)");
    }

    #[test]
    fn description_daily() {
        assert_eq!(Schedule::Interval(86400).description(), "every 1 day(s)");
    }

    #[test]
    fn description_weekly() {
        assert_eq!(
            Schedule::Interval(7 * 86400).description(),
            "every 1 week(s)"
        );
    }

    #[test]
    fn description_disabled() {
        assert_eq!(Schedule::Disabled.description(), "disabled");
    }

    // ── SchedulerState ───────────────────────────────────────────────────

    #[test]
    fn state_default_is_stale() {
        let state = SchedulerState::default();
        // last_run_at == 0 → always stale
        assert!(state.is_stale(3600));
    }

    #[test]
    fn state_recent_run_not_stale() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let state = SchedulerState {
            last_run_at: now,
            ..Default::default()
        };
        assert!(!state.is_stale(3600));
    }

    #[test]
    fn state_old_run_is_stale() {
        let state = SchedulerState {
            last_run_at: 1, // epoch + 1s
            ..Default::default()
        };
        assert!(state.is_stale(3600));
    }

    #[test]
    fn history_capped_at_max() {
        let mut state = SchedulerState::default();
        for i in 0..(MAX_HISTORY + 10) {
            state.push_run(ValidationRunRecord {
                started_at: i as u64,
                finished_at: i as u64 + 1,
                total: 0,
                pass: 0,
                fail: 0,
                unreachable: 0,
                not_checked: 0,
                error: None,
            });
        }
        assert_eq!(state.history.len(), MAX_HISTORY);
        // Oldest entries should have been evicted
        assert_eq!(state.history[0].started_at, 10);
    }

    #[test]
    fn state_round_trip_json() {
        let mut state = SchedulerState {
            schedule: Some(Schedule::Interval(3600)),
            last_run_at: 1_700_000_000,
            last_run: None,
            history: vec![],
        };
        state.push_run(ValidationRunRecord {
            started_at: 1_700_000_000,
            finished_at: 1_700_000_005,
            total: 3,
            pass: 2,
            fail: 1,
            unreachable: 0,
            not_checked: 0,
            error: None,
        });

        let json = serde_json::to_string(&state).unwrap();
        let back: SchedulerState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.last_run_at, state.last_run_at);
        assert_eq!(back.history.len(), 1);
        assert_eq!(back.history[0].pass, 2);
        assert_eq!(back.history[0].fail, 1);
    }

    #[test]
    fn state_save_and_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("validation-state.json");

        let mut state = SchedulerState {
            schedule: Some(Schedule::Interval(7200)),
            last_run_at: 999,
            last_run: None,
            history: vec![],
        };
        state.push_run(ValidationRunRecord {
            started_at: 999,
            finished_at: 1000,
            total: 1,
            pass: 1,
            fail: 0,
            unreachable: 0,
            not_checked: 0,
            error: None,
        });

        state.save(&path).unwrap();
        let loaded = SchedulerState::load(&path).unwrap();
        assert_eq!(loaded.last_run_at, 1000);
        assert_eq!(loaded.history.len(), 1);
        assert_eq!(loaded.schedule, Some(Schedule::Interval(7200)));
    }

    #[test]
    fn state_load_missing_file_returns_default() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.json");
        let state = SchedulerState::load(&path).unwrap();
        assert_eq!(state.last_run_at, 0);
        assert!(state.history.is_empty());
    }

    // ── ValidationRunRecord ──────────────────────────────────────────────

    #[test]
    fn run_record_error_record() {
        let rec = ValidationRunRecord::error_record(100, "vault error");
        assert_eq!(rec.started_at, 100);
        assert_eq!(rec.error.as_deref(), Some("vault error"));
        assert_eq!(rec.total, 0);
    }

    #[test]
    fn run_record_from_report() {
        use crate::validator::{ValidationEntry, ValidationReport, ValidationStatus};
        let report = ValidationReport {
            generated_at: 200,
            total: 2,
            valid: 1,
            invalid: 1,
            unreachable: 0,
            not_checked: 0,
            entries: vec![
                ValidationEntry {
                    name: "KEY_A".to_string(),
                    validator: "openai".to_string(),
                    status: ValidationStatus::Valid,
                    reason: None,
                    checked_at: 200,
                },
                ValidationEntry {
                    name: "KEY_B".to_string(),
                    validator: "stripe".to_string(),
                    status: ValidationStatus::Invalid,
                    reason: Some("401".to_string()),
                    checked_at: 200,
                },
            ],
        };
        let rec = ValidationRunRecord::from_report(200, &report);
        assert_eq!(rec.total, 2);
        assert_eq!(rec.pass, 1);
        assert_eq!(rec.fail, 1);
        assert!(rec.error.is_none());
    }

    // ── state_file_path ──────────────────────────────────────────────────

    #[test]
    fn state_file_path_ends_with_validation_state_json() {
        let p = state_file_path("test-project-id");
        assert!(p.to_string_lossy().ends_with("validation-state.json"));
        assert!(p.to_string_lossy().contains("test-project-id"));
    }
}
