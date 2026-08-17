//! Rotation strategy types for scheduled secret rotation.
//!
//! Supports three schedule patterns:
//!   - `daily@HH:MM`           — rotate every day at the given UTC time
//!   - `weekly@WEEKDAY:HH:MM`  — rotate once a week on the given day/time
//!   - `monthly@DDth:HH:MM`    — rotate once a month on the given day of month
//!
//! The `never` strategy disables automatic rotation.

use serde::{Deserialize, Serialize};

/// Top-level rotation strategy variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationStrategy {
    Never,
    Daily,
    Weekly,
    Monthly,
}

impl RotationStrategy {
    /// Parse from a CLI string (`never`, `daily`, `weekly`, `monthly`).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "never" => Some(Self::Never),
            "daily" => Some(Self::Daily),
            "weekly" => Some(Self::Weekly),
            "monthly" => Some(Self::Monthly),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }
}

impl std::fmt::Display for RotationStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Weekday for weekly schedules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl Weekday {
    /// ISO weekday number: Monday = 0 … Sunday = 6.
    pub fn iso_index(self) -> u8 {
        match self {
            Self::Monday => 0,
            Self::Tuesday => 1,
            Self::Wednesday => 2,
            Self::Thursday => 3,
            Self::Friday => 4,
            Self::Saturday => 5,
            Self::Sunday => 6,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "monday" | "mon" => Some(Self::Monday),
            "tuesday" | "tue" => Some(Self::Tuesday),
            "wednesday" | "wed" => Some(Self::Wednesday),
            "thursday" | "thu" => Some(Self::Thursday),
            "friday" | "fri" => Some(Self::Friday),
            "saturday" | "sat" => Some(Self::Saturday),
            "sunday" | "sun" => Some(Self::Sunday),
            _ => None,
        }
    }
}

/// A fully-specified rotation schedule.
///
/// Stored under `[phantom.rotation_policy]` in `.phantom.toml` and can be
/// overridden per-secret via `[phantom.secrets.{name}]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationSchedule {
    /// High-level strategy.
    pub strategy: RotationStrategy,

    /// For `daily`: hour (0-23) in UTC at which to rotate. Default 2.
    #[serde(default = "default_hour")]
    pub hour: u8,

    /// For `daily`/`weekly`/`monthly`: minute (0-59). Default 0.
    #[serde(default)]
    pub minute: u8,

    /// For `weekly`: day of week (0 = Monday). Default Monday.
    #[serde(default = "default_weekday")]
    pub weekday: Weekday,

    /// For `monthly`: day of month (1-31). Default 1.
    #[serde(default = "default_day_of_month")]
    pub day_of_month: u8,

    /// Unix timestamp of the last successful rotation (managed by the CLI).
    #[serde(default)]
    pub last_rotated: Option<u64>,
}

fn default_hour() -> u8 {
    2
}
fn default_weekday() -> Weekday {
    Weekday::Monday
}
fn default_day_of_month() -> u8 {
    1
}

impl RotationSchedule {
    /// Build a schedule from a CLI `--schedule-strategy` value using sensible
    /// defaults (daily@02:00, weekly@monday:03:00, monthly@1st:00:00).
    pub fn from_strategy(strategy: RotationStrategy) -> Self {
        match strategy {
            RotationStrategy::Never => Self {
                strategy: RotationStrategy::Never,
                hour: 0,
                minute: 0,
                weekday: Weekday::Monday,
                day_of_month: 1,
                last_rotated: None,
            },
            RotationStrategy::Daily => Self {
                strategy: RotationStrategy::Daily,
                hour: 2,
                minute: 0,
                weekday: Weekday::Monday,
                day_of_month: 1,
                last_rotated: None,
            },
            RotationStrategy::Weekly => Self {
                strategy: RotationStrategy::Weekly,
                hour: 3,
                minute: 0,
                weekday: Weekday::Monday,
                day_of_month: 1,
                last_rotated: None,
            },
            RotationStrategy::Monthly => Self {
                strategy: RotationStrategy::Monthly,
                hour: 0,
                minute: 0,
                weekday: Weekday::Monday,
                day_of_month: 1,
                last_rotated: None,
            },
        }
    }

    /// Returns `true` if the schedule requires rotation right now, given
    /// `now_secs` seconds since the Unix epoch (UTC).
    ///
    /// Logic:
    ///   - `Never` → always false.
    ///   - For the others, we check whether the most recent window boundary
    ///     (the last daily/weekly/monthly slot in the past) occurred *after*
    ///     `last_rotated`. If so, rotation is due.
    pub fn should_rotate_now(&self, now_secs: u64) -> bool {
        if self.strategy == RotationStrategy::Never {
            return false;
        }

        let last = self.last_rotated.unwrap_or(0);

        // Find the timestamp of the last schedule window boundary before `now`.
        let boundary = self.last_boundary_before(now_secs);
        match boundary {
            Some(b) => b > last,
            None => false,
        }
    }

    /// Returns the Unix timestamp of the most recent schedule boundary that
    /// falls strictly before `now_secs`, or `None` if the strategy is Never.
    pub fn last_boundary_before(&self, now_secs: u64) -> Option<u64> {
        match self.strategy {
            RotationStrategy::Never => None,
            RotationStrategy::Daily => {
                // Slot fires every day at self.hour:self.minute UTC.
                let slot_secs = (self.hour as u64) * 3600 + (self.minute as u64) * 60;
                let today_midnight = (now_secs / 86_400) * 86_400;
                let today_slot = today_midnight + slot_secs;
                if today_slot <= now_secs {
                    Some(today_slot)
                } else {
                    // Slot hasn't fired yet today — use yesterday's.
                    Some(today_slot.saturating_sub(86_400))
                }
            }
            RotationStrategy::Weekly => {
                // Slot fires once a week on self.weekday at self.hour:self.minute UTC.
                // ISO epoch (1970-01-01) was a Thursday (index 3).
                let days_since_epoch = now_secs / 86_400;
                let current_weekday = (days_since_epoch + 3) % 7; // 0=Monday
                let target_weekday = self.weekday.iso_index() as u64;
                let slot_secs = (self.hour as u64) * 3600 + (self.minute as u64) * 60;

                let days_ago = (current_weekday + 7 - target_weekday) % 7;
                let target_midnight = (days_since_epoch - days_ago) * 86_400;
                let target_slot = target_midnight + slot_secs;
                if target_slot <= now_secs {
                    Some(target_slot)
                } else {
                    // Slot hasn't fired yet this week — use last week's.
                    Some(target_slot.saturating_sub(7 * 86_400))
                }
            }
            RotationStrategy::Monthly => {
                // Slot fires on self.day_of_month each month at self.hour:self.minute UTC.
                // Approximate: use 30-day months for boundary detection.
                let days_since_epoch = now_secs / 86_400;
                // Approximate month boundaries (good enough for scheduling).
                let approx_month = days_since_epoch / 30;
                let month_start_day = approx_month * 30;
                let target_day_offset = (self.day_of_month as u64).saturating_sub(1);
                let slot_secs = (self.hour as u64) * 3600 + (self.minute as u64) * 60;
                let target_slot = (month_start_day + target_day_offset) * 86_400 + slot_secs;

                if target_slot <= now_secs {
                    Some(target_slot)
                } else {
                    // Slot hasn't fired yet this month — use last month's.
                    let prev_month_start = month_start_day.saturating_sub(30);
                    Some((prev_month_start + target_day_offset) * 86_400 + slot_secs)
                }
            }
        }
    }

    /// Human-readable description of the schedule, e.g. "daily@02:00 UTC".
    pub fn describe(&self) -> String {
        match self.strategy {
            RotationStrategy::Never => "never".to_string(),
            RotationStrategy::Daily => {
                format!("daily@{:02}:{:02} UTC", self.hour, self.minute)
            }
            RotationStrategy::Weekly => {
                format!(
                    "weekly@{:?}:{:02}:{:02} UTC",
                    self.weekday, self.hour, self.minute
                )
            }
            RotationStrategy::Monthly => {
                format!(
                    "monthly@{}th:{:02}:{:02} UTC",
                    self.day_of_month, self.hour, self.minute
                )
            }
        }
    }
}

/// How many seconds ago was `last_rotated` relative to `now_secs`?
/// Returns `None` if `last_rotated` is `None` (never rotated).
pub fn seconds_overdue(schedule: &RotationSchedule, now_secs: u64) -> Option<i64> {
    let boundary = schedule.last_boundary_before(now_secs)?;
    let last = schedule.last_rotated?;
    if boundary > last {
        Some((now_secs as i64) - (boundary as i64))
    } else {
        None
    }
}

// ── Rotation enforcement gate ─────────────────────────────────────────────────

/// Period in seconds for each `RotationStrategy` variant.
/// Used by the enforcement gate to determine how long ago `last_rotated` must
/// have been to be considered overdue.
pub fn strategy_period_secs(strategy: &RotationStrategy) -> Option<u64> {
    match strategy {
        RotationStrategy::Never => None,
        RotationStrategy::Daily => Some(86_400),
        RotationStrategy::Weekly => Some(7 * 86_400),
        RotationStrategy::Monthly => Some(30 * 86_400),
    }
}

/// Result of the rotation enforcement gate check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationEnforcementStatus {
    /// Rotation enforcement is disabled for this secret.
    Disabled,
    /// The schedule is `Never` — enforcement is not applicable.
    NotApplicable,
    /// Secret has never been rotated but enforcement requires it.
    NeverRotated,
    /// Secret is within its rotation window — access is allowed.
    Ok,
    /// Secret is overdue for rotation. Contains the age in seconds and a
    /// human-readable schedule description for the error message.
    Overdue {
        /// How many seconds ago the secret was last rotated (or 0 if never).
        last_rotated_secs_ago: u64,
        /// Human-readable schedule name, e.g. `"weekly"`.
        schedule_label: String,
    },
}

impl RotationEnforcementStatus {
    /// Returns `true` when `phantom exec` must be blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(
            self,
            RotationEnforcementStatus::Overdue { .. } | RotationEnforcementStatus::NeverRotated
        )
    }

    /// Build the error message shown to the user when blocked.
    ///
    /// Example: `"Secret API_KEY last rotated 40 days ago (schedule: weekly). Run \`phantom rotate API_KEY\` to unlock."`
    pub fn error_message(&self, secret_name: &str) -> Option<String> {
        match self {
            RotationEnforcementStatus::NeverRotated => Some(format!(
                "Secret '{secret_name}' has never been rotated (rotation enforcement is on). \
                 Run `phantom rotate {secret_name}` to unlock."
            )),
            RotationEnforcementStatus::Overdue {
                last_rotated_secs_ago,
                schedule_label,
            } => {
                let days = last_rotated_secs_ago / 86_400;
                let unit = if days == 1 { "day" } else { "days" };
                Some(format!(
                    "Secret '{secret_name}' last rotated {days} {unit} ago \
                     (schedule: {schedule_label}). \
                     Run `phantom rotate {secret_name}` to unlock."
                ))
            }
            _ => None,
        }
    }
}

/// Check whether a secret with `enforce_rotation_on_access = true` should block
/// access given its rotation schedule and current time.
///
/// * `enforce` — the value of `SecretOverride::enforce_rotation_on_access`.
/// * `schedule` — the effective `RotationSchedule` for this secret (if any).
/// * `now_secs` — current Unix timestamp (injectable for tests).
pub fn check_rotation_enforcement(
    enforce: bool,
    schedule: Option<&RotationSchedule>,
    now_secs: u64,
) -> RotationEnforcementStatus {
    if !enforce {
        return RotationEnforcementStatus::Disabled;
    }

    let Some(sched) = schedule else {
        return RotationEnforcementStatus::NotApplicable;
    };

    let Some(period) = strategy_period_secs(&sched.strategy) else {
        // Strategy::Never — enforcement not applicable.
        return RotationEnforcementStatus::NotApplicable;
    };

    let Some(last_rotated) = sched.last_rotated else {
        return RotationEnforcementStatus::NeverRotated;
    };

    let age = now_secs.saturating_sub(last_rotated);
    if age >= period {
        RotationEnforcementStatus::Overdue {
            last_rotated_secs_ago: age,
            schedule_label: sched.strategy.as_str().to_string(),
        }
    } else {
        RotationEnforcementStatus::Ok
    }
}

// ── Expiry enforcement ────────────────────────────────────────────────────────

/// Status of a single secret's TTL-based expiry as returned by
/// [`check_expiry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpiryStatus {
    /// No `expires_at` is set; expiry enforcement is not applicable.
    NoExpiry,
    /// The secret is still within its TTL. `days_remaining` is the number of
    /// whole days left (always ≥ 1).
    Valid { days_remaining: u64 },
    /// The secret expires within the given grace period (0 < days_remaining ≤ grace_days).
    GracePeriod { days_remaining: u64 },
    /// The secret has already expired.
    Expired { secs_overdue: u64 },
}

impl ExpiryStatus {
    /// Return `true` if the secret is expired (used by enforce logic).
    pub fn is_expired(&self) -> bool {
        matches!(self, ExpiryStatus::Expired { .. })
    }

    /// Return `true` if the secret is valid and not in grace period.
    pub fn is_valid(&self) -> bool {
        matches!(self, ExpiryStatus::Valid { .. })
    }

    /// Human-readable label for display.
    pub fn label(&self) -> String {
        match self {
            ExpiryStatus::NoExpiry => "no expiry set".to_string(),
            ExpiryStatus::Valid { days_remaining } => {
                format!("{days_remaining} day(s) remaining")
            }
            ExpiryStatus::GracePeriod { days_remaining } => {
                format!("WARNING: expires in {days_remaining} day(s)")
            }
            ExpiryStatus::Expired { secs_overdue } => {
                let days = secs_overdue / 86_400;
                if days == 0 {
                    "EXPIRED (today)".to_string()
                } else {
                    format!("EXPIRED ({days} day(s) overdue)")
                }
            }
        }
    }
}

/// Check the expiry status of a single secret given:
/// - `expires_at`   — the Unix timestamp stored in `.phantom.toml` (or vault metadata)
/// - `grace_days`   — number of days before expiry at which we issue a warning
/// - `now_secs`     — current time (seconds since Unix epoch); injectable for tests
pub fn check_expiry(expires_at: u64, grace_days: u64, now_secs: u64) -> ExpiryStatus {
    if now_secs >= expires_at {
        let secs_overdue = now_secs - expires_at;
        return ExpiryStatus::Expired { secs_overdue };
    }

    let secs_remaining = expires_at - now_secs;
    let days_remaining = secs_remaining / 86_400;

    if days_remaining <= grace_days {
        ExpiryStatus::GracePeriod { days_remaining }
    } else {
        ExpiryStatus::Valid { days_remaining }
    }
}

/// Compute a new `expires_at` timestamp that is `rotation_window_days` from
/// `now_secs`. Used by `phantom expiry rotate` to reset the expiry timer.
pub fn compute_new_expires_at(rotation_window_days: u64, now_secs: u64) -> u64 {
    now_secs + rotation_window_days * 86_400
}

/// Compute the next scheduled rotation time after `now_secs`.
///
/// Returns `None` when strategy is `Never` or if `now_secs` wraps.
pub fn next_rotation_after(schedule: &RotationSchedule, now_secs: u64) -> Option<u64> {
    match schedule.strategy {
        RotationStrategy::Never => None,
        RotationStrategy::Daily => {
            let slot_secs = (schedule.hour as u64) * 3600 + (schedule.minute as u64) * 60;
            let today_midnight = (now_secs / 86_400) * 86_400;
            let today_slot = today_midnight + slot_secs;
            if today_slot > now_secs {
                Some(today_slot)
            } else {
                Some(today_slot + 86_400)
            }
        }
        RotationStrategy::Weekly => {
            let days_since_epoch = now_secs / 86_400;
            let current_weekday = (days_since_epoch + 3) % 7;
            let target_weekday = schedule.weekday.iso_index() as u64;
            let slot_secs = (schedule.hour as u64) * 3600 + (schedule.minute as u64) * 60;
            let days_until = (target_weekday + 7 - current_weekday) % 7;
            let candidate_day = days_since_epoch + days_until;
            let candidate_slot = candidate_day * 86_400 + slot_secs;
            if candidate_slot > now_secs {
                Some(candidate_slot)
            } else {
                Some(candidate_slot + 7 * 86_400)
            }
        }
        RotationStrategy::Monthly => {
            let days_since_epoch = now_secs / 86_400;
            let approx_month = days_since_epoch / 30;
            let month_start_day = approx_month * 30;
            let target_day_offset = (schedule.day_of_month as u64).saturating_sub(1);
            let slot_secs = (schedule.hour as u64) * 3600 + (schedule.minute as u64) * 60;
            let this_month_slot = (month_start_day + target_day_offset) * 86_400 + slot_secs;
            if this_month_slot > now_secs {
                Some(this_month_slot)
            } else {
                Some(this_month_slot + 30 * 86_400)
            }
        }
    }
}

/// Severity level returned by the doctor grace-period check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracePeriodSeverity {
    /// Secret is healthy — more than `grace_period_secs` remain.
    Ok,
    /// Secret expires within the grace period — promote to warning in `phantom doctor`.
    Warning { days_remaining: u64 },
    /// Secret has already expired.
    Expired { secs_overdue: u64 },
    /// No expiry set; grace-period check is not applicable.
    NoExpiry,
}

impl GracePeriodSeverity {
    /// Returns `true` when `phantom doctor` should display a warning.
    pub fn is_doctor_warning(&self) -> bool {
        matches!(
            self,
            GracePeriodSeverity::Warning { .. } | GracePeriodSeverity::Expired { .. }
        )
    }
}

/// Check whether a secret falls within its expiry grace period.
///
/// * `expires_at`         — Unix timestamp of the secret's expiry (from vault metadata).
/// * `grace_period_secs`  — From `SecretOverride::expiry_grace_period_secs` (default 604800).
/// * `now_secs`           — Current Unix timestamp (injectable for tests).
pub fn check_grace_period(
    expires_at: Option<u64>,
    grace_period_secs: u64,
    now_secs: u64,
) -> GracePeriodSeverity {
    let Some(exp) = expires_at else {
        return GracePeriodSeverity::NoExpiry;
    };

    if now_secs >= exp {
        return GracePeriodSeverity::Expired {
            secs_overdue: now_secs - exp,
        };
    }

    let secs_remaining = exp - now_secs;
    if secs_remaining <= grace_period_secs {
        let days_remaining = secs_remaining / 86_400;
        GracePeriodSeverity::Warning { days_remaining }
    } else {
        GracePeriodSeverity::Ok
    }
}

/// Returns a human-readable "N days past schedule" string, or `None` if not overdue.
pub fn overdue_description(schedule: &RotationSchedule, now_secs: u64) -> Option<String> {
    let secs = seconds_overdue(schedule, now_secs)?;
    if secs <= 0 {
        return None;
    }
    let days = secs / 86_400;
    if days == 0 {
        Some("less than 1 day past schedule".to_string())
    } else if days == 1 {
        Some("1 day past schedule".to_string())
    } else {
        Some(format!("{days} days past schedule"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// Build a fixed "now" timestamp: 2026-06-29 04:00:00 UTC
    /// 1970-01-01 → 2026-06-29 = 20633 days.
    fn base_now() -> u64 {
        20633 * 86_400 + 4 * 3600 // 04:00 UTC
    }

    // ── Never ──────────────────────────────────────────────────────────────────

    #[test]
    fn never_never_rotates() {
        let sched = RotationSchedule::from_strategy(RotationStrategy::Never);
        assert!(!sched.should_rotate_now(base_now()));
        assert!(!sched.should_rotate_now(0));
        assert!(!sched.should_rotate_now(u64::MAX / 2));
    }

    // ── Daily ──────────────────────────────────────────────────────────────────

    #[test]
    fn daily_rotates_after_slot_passed_and_never_rotated() {
        // hour=02, now=04:00 → slot was at 02:00 today → boundary < now, never rotated
        let sched = RotationSchedule {
            strategy: RotationStrategy::Daily,
            hour: 2,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: None,
        };
        assert!(sched.should_rotate_now(base_now()));
    }

    #[test]
    fn daily_does_not_rotate_before_slot() {
        // now = 01:00 UTC, slot = 02:00 → today's slot hasn't fired yet
        let now = 20633 * 86_400 + 3600; // 01:00
        let sched = RotationSchedule {
            strategy: RotationStrategy::Daily,
            hour: 2,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            // last_rotated = yesterday's slot (23 h ago)
            last_rotated: Some(20632 * 86_400 + 2 * 3600),
        };
        assert!(!sched.should_rotate_now(now));
    }

    #[test]
    fn daily_does_not_rotate_if_already_rotated_today() {
        let now = base_now(); // 04:00
        let today_slot = 20633 * 86_400 + 2 * 3600; // 02:00 today
        let sched = RotationSchedule {
            strategy: RotationStrategy::Daily,
            hour: 2,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: Some(today_slot + 60), // rotated after the slot
        };
        assert!(!sched.should_rotate_now(now));
    }

    #[test]
    fn daily_rotates_when_missed_yesterday() {
        // last_rotated = 2 days ago, slot fires every day at 02:00
        let now = base_now(); // today 04:00
        let sched = RotationSchedule {
            strategy: RotationStrategy::Daily,
            hour: 2,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: Some(20631 * 86_400 + 2 * 3600), // 2 days ago
        };
        assert!(sched.should_rotate_now(now));
    }

    // ── Weekly ─────────────────────────────────────────────────────────────────

    #[test]
    fn weekly_rotates_when_never_rotated() {
        // 2026-06-29 is a Monday (ISO weekday 0).
        // now = Monday 04:00, slot = Monday@03:00 → boundary is this morning at 03:00.
        let now = 20633 * 86_400 + 4 * 3600;
        let sched = RotationSchedule {
            strategy: RotationStrategy::Weekly,
            hour: 3,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: None,
        };
        assert!(sched.should_rotate_now(now));
    }

    #[test]
    fn weekly_does_not_rotate_before_slot_this_week() {
        // now = Monday 01:00, slot = Monday@03:00 → today's slot hasn't fired.
        // last_rotated = last Monday's slot.
        let now = 20633 * 86_400 + 3600;
        let last_monday_slot = 20626 * 86_400 + 3 * 3600;
        let sched = RotationSchedule {
            strategy: RotationStrategy::Weekly,
            hour: 3,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: Some(last_monday_slot + 60),
        };
        assert!(!sched.should_rotate_now(now));
    }

    // ── Monthly ────────────────────────────────────────────────────────────────

    #[test]
    fn monthly_rotates_when_never_rotated() {
        let sched = RotationSchedule {
            strategy: RotationStrategy::Monthly,
            hour: 0,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: None,
        };
        // Any time after the 1st of the approximate month is fine.
        assert!(sched.should_rotate_now(base_now()));
    }

    #[test]
    fn monthly_does_not_rotate_if_already_rotated_this_month() {
        let now = base_now();
        // Find what boundary monthly would give and set last_rotated after it.
        let sched_unrotated = RotationSchedule {
            strategy: RotationStrategy::Monthly,
            hour: 0,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: None,
        };
        let boundary = sched_unrotated.last_boundary_before(now).unwrap();
        let sched = RotationSchedule {
            last_rotated: Some(boundary + 60),
            ..sched_unrotated
        };
        assert!(!sched.should_rotate_now(now));
    }

    // ── Parse helpers ──────────────────────────────────────────────────────────

    #[test]
    fn strategy_from_str_all_variants() {
        assert_eq!(
            RotationStrategy::from_str("never"),
            Some(RotationStrategy::Never)
        );
        assert_eq!(
            RotationStrategy::from_str("daily"),
            Some(RotationStrategy::Daily)
        );
        assert_eq!(
            RotationStrategy::from_str("weekly"),
            Some(RotationStrategy::Weekly)
        );
        assert_eq!(
            RotationStrategy::from_str("monthly"),
            Some(RotationStrategy::Monthly)
        );
        assert_eq!(RotationStrategy::from_str("bogus"), None);
    }

    #[test]
    fn describe_formats_correctly() {
        let d = RotationSchedule::from_strategy(RotationStrategy::Daily);
        assert!(d.describe().starts_with("daily@"));

        let w = RotationSchedule::from_strategy(RotationStrategy::Weekly);
        assert!(w.describe().starts_with("weekly@"));

        let m = RotationSchedule::from_strategy(RotationStrategy::Monthly);
        assert!(m.describe().starts_with("monthly@"));

        let n = RotationSchedule::from_strategy(RotationStrategy::Never);
        assert_eq!(n.describe(), "never");
    }

    #[test]
    fn overdue_description_returns_none_when_not_overdue() {
        let now = base_now();
        let sched_unrotated = RotationSchedule {
            strategy: RotationStrategy::Daily,
            hour: 2,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: None,
        };
        let b = sched_unrotated.last_boundary_before(now).unwrap();
        let sched = RotationSchedule {
            last_rotated: Some(b + 1),
            ..sched_unrotated
        };
        assert!(overdue_description(&sched, now).is_none());
    }

    #[test]
    fn overdue_description_returns_days_when_overdue() {
        let now = base_now();
        let sched = RotationSchedule {
            strategy: RotationStrategy::Daily,
            hour: 2,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: Some(now - 6 * 86_400), // 6 days ago
        };
        let desc = overdue_description(&sched, now);
        assert!(desc.is_some());
        let s = desc.unwrap();
        assert!(
            s.contains("past schedule"),
            "expected 'past schedule' in: {s}"
        );
    }
}
