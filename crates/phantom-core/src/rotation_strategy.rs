//! Rotation strategy types for scheduled secret rotation.
//!
//! Supports three schedule patterns:
//!   - `daily@HH:MM`           — rotate every day at the given UTC time
//!   - `weekly@WEEKDAY:HH:MM`  — rotate once a week on the given day/time
//!   - `monthly@DDth:HH:MM`    — rotate once a month on the given day of month
//!   - `interval`              — rotate a fixed number of days after the last
//!     rotation (from a per-secret `rotate_every = "90d"`)
//!
//! The `never` strategy disables automatic rotation.

use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

/// Seconds in one day.
const DAY_SECS: u64 = 86_400;

/// Top-level rotation strategy variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationStrategy {
    Never,
    Daily,
    Weekly,
    Monthly,
    /// Rotate a fixed number of days after `last_rotated` (a never-rotated
    /// secret is due now). Written in TOML as `strategy = { interval = 90 }`.
    Interval(NonZeroU64),
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
            Self::Interval(_) => "interval",
        }
    }

    /// Human-readable label: the strategy name, or `every N days`.
    pub fn to_label(&self) -> String {
        match self {
            Self::Interval(days) if days.get() == 1 => "every 1 day".to_string(),
            Self::Interval(days) => format!("every {days} days"),
            other => other.as_str().to_string(),
        }
    }

    /// The exact interval in days for [`RotationStrategy::Interval`].
    pub fn interval_days(&self) -> Option<u64> {
        match self {
            Self::Interval(days) => Some(days.get()),
            _ => None,
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
            RotationStrategy::Interval(days) => Self {
                strategy: RotationStrategy::Interval(days),
                hour: 0,
                minute: 0,
                weekday: Weekday::Monday,
                day_of_month: 1,
                last_rotated: None,
            },
        }
    }

    /// When an interval schedule falls due: `interval` days after
    /// `last_rotated`, or after the epoch when never rotated (so it is due).
    fn interval_due_at(&self, days: NonZeroU64) -> u64 {
        self.last_rotated
            .unwrap_or(0)
            .saturating_add(days.get().saturating_mul(DAY_SECS))
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
            RotationStrategy::Interval(days) => {
                let due = self.interval_due_at(days);
                if due <= now_secs {
                    Some(due)
                } else {
                    // Not due yet: the last boundary is the rotation itself.
                    Some(self.last_rotated.unwrap_or(0))
                }
            }
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
                // Slot fires on self.day_of_month of each calendar month at
                // self.hour:self.minute UTC (the month's last day when shorter).
                let (year, month) = year_month_of(now_secs);
                let this_month = self.monthly_slot(year, month);
                if this_month <= now_secs {
                    Some(this_month)
                } else {
                    let (year, month) = previous_month(year, month);
                    Some(self.monthly_slot(year, month))
                }
            }
        }
    }

    /// The monthly slot in the given calendar month, clamped to the month's
    /// last day and to the epoch.
    fn monthly_slot(&self, year: i64, month: u32) -> u64 {
        let day = u32::from(self.day_of_month).clamp(1, days_in_month(year, month));
        let slot_secs = (self.hour as i64) * 3600 + (self.minute as i64) * 60;
        let secs = days_from_civil(year, month, day)
            .saturating_mul(86_400)
            .saturating_add(slot_secs);
        u64::try_from(secs).unwrap_or(0)
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
                    "monthly@{}{}:{:02}:{:02} UTC",
                    self.day_of_month,
                    ordinal_suffix(self.day_of_month),
                    self.hour,
                    self.minute
                )
            }
            RotationStrategy::Interval(_) => self.strategy.to_label(),
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
/// Used by the enforcement gate to decide how old a secret may be before
/// access is refused. `Monthly` is a fixed 30 days here, so a monthly secret
/// is refused at most a day earlier than a calendar month would allow.
pub fn strategy_period_secs(strategy: &RotationStrategy) -> Option<u64> {
    match strategy {
        RotationStrategy::Never => None,
        RotationStrategy::Daily => Some(86_400),
        RotationStrategy::Weekly => Some(7 * 86_400),
        RotationStrategy::Monthly => Some(30 * 86_400),
        RotationStrategy::Interval(days) => Some(days.get().saturating_mul(DAY_SECS)),
    }
}

/// Result of the rotation enforcement gate check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationEnforcementStatus {
    /// Rotation enforcement is disabled for this secret.
    Disabled,
    /// Enforcement is on, but the secret has no rotation schedule (or its
    /// schedule is `never`), so there is no period to enforce. Blocked: the
    /// configuration asks for something Phantom cannot check.
    NoSchedule,
    /// Enforcement is on, but there is no trustworthy timestamp to measure the
    /// secret's age from. Blocked.
    NoAnchor,
    /// The age anchor lies in the future (clock change or edited metadata), so
    /// the secret's age is unknown. Blocked.
    AnchorInFuture,
    /// Secret is within its rotation window — access is allowed.
    Ok,
    /// Secret is overdue for rotation. Contains the age in seconds and a
    /// human-readable schedule description for the error message.
    Overdue {
        /// Seconds since the age anchor.
        last_rotated_secs_ago: u64,
        /// Human-readable schedule name, e.g. `"weekly"`.
        schedule_label: String,
    },
}

impl RotationEnforcementStatus {
    /// Returns `true` when access must be refused.
    pub fn is_blocked(&self) -> bool {
        !matches!(
            self,
            RotationEnforcementStatus::Disabled | RotationEnforcementStatus::Ok
        )
    }

    /// Build the message shown when access is refused. It names the secret
    /// and the fix, and never contains a secret value.
    pub fn error_message(&self, secret_name: &str) -> Option<String> {
        let fix = format!(
            "Rotate the credential at its provider, then replace it from a trusted terminal with \
             `phantom remove {secret_name}` followed by `phantom add {secret_name}`, or set \
             `enforce_rotation_on_access = false` under [phantom.secrets.{secret_name}] in .phantom.toml."
        );
        let reason = match self {
            RotationEnforcementStatus::Disabled | RotationEnforcementStatus::Ok => return None,
            RotationEnforcementStatus::NoSchedule => format!(
                "Secret '{secret_name}' has enforce_rotation_on_access = true but no rotation \
                 schedule to enforce; set `rotate_every` (such as \"90d\") under \
                 [phantom.secrets.{secret_name}] or a [phantom.rotation_policy]."
            ),
            RotationEnforcementStatus::NoAnchor => format!(
                "Secret '{secret_name}' has rotation enforcement on, but its vault entry records \
                 no time it was stored or rotated, so its age is unknown."
            ),
            RotationEnforcementStatus::AnchorInFuture => format!(
                "Secret '{secret_name}' has rotation enforcement on, but its vault entry records \
                 a store or rotation time in the future, so its age is unknown."
            ),
            RotationEnforcementStatus::Overdue {
                last_rotated_secs_ago,
                schedule_label,
            } => {
                let days = last_rotated_secs_ago / 86_400;
                let unit = if days == 1 { "day" } else { "days" };
                format!(
                    "Secret '{secret_name}' was stored or last rotated {days} {unit} ago \
                     (schedule: {schedule_label}) and is overdue for rotation."
                )
            }
        };
        if matches!(self, RotationEnforcementStatus::NoSchedule) {
            return Some(format!(
                "{reason} Or set `enforce_rotation_on_access = false` under \
                 [phantom.secrets.{secret_name}] in .phantom.toml."
            ));
        }
        Some(format!("{reason} {fix}"))
    }
}

/// Check whether a secret with `enforce_rotation_on_access = true` must be
/// refused, given its rotation schedule and age anchor.
///
/// * `enforce` — the value of `SecretOverride::enforce_rotation_on_access`.
/// * `schedule` — the effective `RotationSchedule` for this secret (if any).
/// * `anchor` — Unix time the secret's current value is known to be no older
///   than (the caller derives it from machine-local vault metadata). The
///   schedule's own `last_rotated` is deliberately ignored: it lives in the
///   committed `.phantom.toml`, no Phantom command writes it, and a hand-set
///   value would otherwise unlock the gate.
/// * `now_secs` — current Unix timestamp (injectable for tests).
///
/// Every state other than "disabled" and "provably within the window"
/// blocks, so a missing schedule or anchor fails closed.
pub fn check_rotation_enforcement(
    enforce: bool,
    schedule: Option<&RotationSchedule>,
    anchor: Option<u64>,
    now_secs: u64,
) -> RotationEnforcementStatus {
    if !enforce {
        return RotationEnforcementStatus::Disabled;
    }

    let Some(sched) = schedule else {
        return RotationEnforcementStatus::NoSchedule;
    };

    let Some(period) = strategy_period_secs(&sched.strategy) else {
        return RotationEnforcementStatus::NoSchedule;
    };

    let Some(anchor) = anchor else {
        return RotationEnforcementStatus::NoAnchor;
    };
    if anchor > now_secs {
        return RotationEnforcementStatus::AnchorInFuture;
    }

    let age = now_secs - anchor;
    if age >= period {
        RotationEnforcementStatus::Overdue {
            last_rotated_secs_ago: age,
            schedule_label: sched.strategy.to_label(),
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
        // An overdue interval schedule is due now.
        RotationStrategy::Interval(days) => Some(schedule.interval_due_at(days).max(now_secs)),
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
            let (year, month) = year_month_of(now_secs);
            let this_month = schedule.monthly_slot(year, month);
            if this_month > now_secs {
                Some(this_month)
            } else {
                let (year, month) = next_month(year, month);
                Some(schedule.monthly_slot(year, month))
            }
        }
    }
}

// ── Calendar helpers (UTC, proleptic Gregorian) ───────────────────────────────

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The UTC calendar year and month (1-12) containing `secs`.
fn year_month_of(secs: u64) -> (i64, u32) {
    let days = (secs / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month as u32)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    let (next_year, next) = next_month(year, month);
    (days_from_civil(next_year, next, 1) - days_from_civil(year, month, 1)) as u32
}

fn next_month(year: i64, month: u32) -> (i64, u32) {
    if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    }
}

fn previous_month(year: i64, month: u32) -> (i64, u32) {
    if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    }
}

fn ordinal_suffix(day: u8) -> &'static str {
    match (day % 10, day % 100) {
        (_, 11..=13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
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

    /// Monthly slots fell on 30-day blocks counted from 1970, so "the 1st"
    /// could land on any calendar day. They now follow calendar months.
    #[test]
    fn monthly_slots_follow_calendar_months() {
        let monthly = |day_of_month: u8| RotationSchedule {
            strategy: RotationStrategy::Monthly,
            hour: 4,
            minute: 30,
            weekday: Weekday::Monday,
            day_of_month,
            last_rotated: None,
        };
        // 2026-10-26 12:00 UTC.
        let now = 1_793_016_000;
        // 2026-10-01 04:30 and 2026-11-01 04:30 UTC.
        assert_eq!(monthly(1).last_boundary_before(now), Some(1_790_829_000));
        assert_eq!(next_rotation_after(&monthly(1), now), Some(1_793_507_400));
        assert_eq!(monthly(1).describe(), "monthly@1st:04:30 UTC");
        assert_eq!(monthly(22).describe(), "monthly@22nd:04:30 UTC");
        assert_eq!(monthly(13).describe(), "monthly@13th:04:30 UTC");

        // A day the month lacks is its last day: 31 in February 2026 is the
        // 28th, in a leap February the 29th, and March still gets the 31st.
        let midnight = |day: u8| RotationSchedule {
            hour: 0,
            minute: 0,
            ..monthly(day)
        };
        // 2026-02-10, 2026-02-28, 2026-03-31 at 00:00 UTC.
        assert_eq!(
            next_rotation_after(&midnight(31), 1_770_681_600),
            Some(1_772_236_800)
        );
        assert_eq!(
            next_rotation_after(&midnight(31), 1_772_236_800),
            Some(1_774_915_200)
        );
        // 2024-02-10 → 2024-02-29; 2026-02-10 looks back to 2026-01-31.
        assert_eq!(
            next_rotation_after(&midnight(31), 1_707_523_200),
            Some(1_709_164_800)
        );
        assert_eq!(
            midnight(31).last_boundary_before(1_770_681_600),
            Some(1_769_817_600)
        );
    }

    #[test]
    fn calendar_helpers_round_trip_across_eras() {
        for (year, month, day) in [(1970, 1, 1), (2000, 2, 29), (2026, 12, 31), (2100, 3, 1)] {
            let days = days_from_civil(year, month, day);
            assert_eq!(year_month_of(days as u64 * 86_400 + 3_600), (year, month));
        }
        assert_eq!(days_in_month(2100, 2), 28);
        assert_eq!(days_in_month(2000, 2), 29);
        assert_eq!(days_in_month(2026, 4), 30);
        // The far future saturates instead of overflowing.
        let monthly = RotationSchedule::from_strategy(RotationStrategy::Monthly);
        assert!(next_rotation_after(&monthly, u64::MAX).is_some());
        assert!(monthly.last_boundary_before(u64::MAX).is_some());
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

    fn interval(days: u64, last_rotated: Option<u64>) -> RotationSchedule {
        RotationSchedule {
            last_rotated,
            ..RotationSchedule::from_strategy(RotationStrategy::Interval(
                NonZeroU64::new(days).unwrap(),
            ))
        }
    }

    #[test]
    fn interval_is_due_exactly_after_its_length() {
        let now = base_now();
        // Rotated 89 days ago on a 90-day interval: one day left.
        let sched = interval(90, Some(now - 89 * DAY_SECS));
        assert!(!sched.should_rotate_now(now));
        assert_eq!(next_rotation_after(&sched, now), Some(now + DAY_SECS));
        assert!(overdue_description(&sched, now).is_none());
        // A monthly schedule would have been due after 30 days; this one is not.
        assert!(!interval(90, Some(now - 31 * DAY_SECS)).should_rotate_now(now));
        // Rotated 92 days ago: two days past schedule.
        let late = interval(90, Some(now - 92 * DAY_SECS));
        assert!(late.should_rotate_now(now));
        assert_eq!(next_rotation_after(&late, now), Some(now));
        assert_eq!(
            overdue_description(&late, now).as_deref(),
            Some("2 days past schedule")
        );
    }

    #[test]
    fn never_rotated_interval_is_due() {
        let now = base_now();
        let sched = interval(365, None);
        assert!(sched.should_rotate_now(now));
        assert_eq!(next_rotation_after(&sched, now), Some(now));
    }

    #[test]
    fn interval_describes_and_enforces_its_exact_length() {
        let now = base_now();
        assert_eq!(interval(90, None).describe(), "every 90 days");
        assert_eq!(interval(1, None).describe(), "every 1 day");
        assert_eq!(interval(90, None).strategy.as_str(), "interval");
        assert_eq!(
            strategy_period_secs(&interval(90, None).strategy),
            Some(90 * DAY_SECS)
        );
        let sched = interval(90, None);
        assert_eq!(
            check_rotation_enforcement(true, Some(&sched), Some(now - 60 * DAY_SECS), now),
            RotationEnforcementStatus::Ok
        );
        assert_eq!(
            check_rotation_enforcement(true, Some(&sched), Some(now - 95 * DAY_SECS), now),
            RotationEnforcementStatus::Overdue {
                last_rotated_secs_ago: 95 * DAY_SECS,
                schedule_label: "every 90 days".to_string(),
            }
        );
    }

    /// The gate measures age from the caller's vault-derived anchor. A
    /// `last_rotated` committed in `.phantom.toml` must not unlock it.
    #[test]
    fn enforcement_ignores_the_config_last_rotated() {
        let now = base_now();
        let committed_fresh = interval(90, Some(now));
        let status = check_rotation_enforcement(
            true,
            Some(&committed_fresh),
            Some(now - 95 * DAY_SECS),
            now,
        );
        assert!(status.is_blocked(), "got {status:?}");
        let committed_future = interval(90, Some(u64::MAX));
        assert!(check_rotation_enforcement(
            true,
            Some(&committed_future),
            Some(now - 95 * DAY_SECS),
            now
        )
        .is_blocked());
    }

    #[test]
    fn enforcement_fails_closed_without_a_schedule_or_anchor() {
        let now = base_now();
        let sched = interval(90, None);
        let never = RotationSchedule::from_strategy(RotationStrategy::Never);
        for (status, expected) in [
            (
                check_rotation_enforcement(true, None, Some(now), now),
                RotationEnforcementStatus::NoSchedule,
            ),
            (
                check_rotation_enforcement(true, Some(&never), Some(now), now),
                RotationEnforcementStatus::NoSchedule,
            ),
            (
                check_rotation_enforcement(true, Some(&sched), None, now),
                RotationEnforcementStatus::NoAnchor,
            ),
            (
                check_rotation_enforcement(true, Some(&sched), Some(now + 60), now),
                RotationEnforcementStatus::AnchorInFuture,
            ),
        ] {
            assert_eq!(status, expected);
            assert!(status.is_blocked(), "{expected:?} must block");
        }
    }

    #[test]
    fn disabled_enforcement_never_blocks() {
        let now = base_now();
        let sched = interval(90, None);
        for anchor in [None, Some(0), Some(now + 60)] {
            let status = check_rotation_enforcement(false, Some(&sched), anchor, now);
            assert_eq!(status, RotationEnforcementStatus::Disabled);
            assert!(!status.is_blocked());
            assert!(status.error_message("API_KEY").is_none());
        }
        assert_eq!(
            check_rotation_enforcement(false, None, None, now),
            RotationEnforcementStatus::Disabled
        );
    }

    #[test]
    fn enforcement_boundary_is_one_full_period() {
        let now = base_now();
        let weekly = RotationSchedule::from_strategy(RotationStrategy::Weekly);
        let just_inside = now - 7 * DAY_SECS + 1;
        assert_eq!(
            check_rotation_enforcement(true, Some(&weekly), Some(just_inside), now),
            RotationEnforcementStatus::Ok
        );
        assert!(
            check_rotation_enforcement(true, Some(&weekly), Some(now - 7 * DAY_SECS), now)
                .is_blocked()
        );
    }

    #[test]
    fn enforcement_messages_name_the_secret_and_a_real_fix() {
        let now = base_now();
        let sched = interval(90, None);
        let overdue =
            check_rotation_enforcement(true, Some(&sched), Some(now - 95 * DAY_SECS), now);
        let message = overdue.error_message("API_KEY").unwrap();
        assert!(message.contains("'API_KEY'"));
        assert!(message.contains("95 days ago"));
        assert!(message.contains("every 90 days"));
        assert!(message.contains("`phantom remove API_KEY` followed by `phantom add API_KEY`"));
        assert!(message.contains("enforce_rotation_on_access = false"));
        // `phantom rotate NAME` does not replace a credential in this release.
        assert!(!message.contains("phantom rotate"));
        for status in [
            RotationEnforcementStatus::NoAnchor,
            RotationEnforcementStatus::AnchorInFuture,
        ] {
            let message = status.error_message("API_KEY").unwrap();
            assert!(message.contains("'API_KEY'") && message.contains("phantom remove API_KEY"));
        }
        let message = RotationEnforcementStatus::NoSchedule
            .error_message("API_KEY")
            .unwrap();
        assert!(message.contains("rotate_every"));
        assert!(message.contains("enforce_rotation_on_access = false"));
    }

    #[test]
    fn huge_interval_saturates_instead_of_wrapping() {
        let now = base_now();
        let sched = interval(u64::MAX, Some(now));
        assert!(!sched.should_rotate_now(now));
        assert_eq!(next_rotation_after(&sched, now), Some(u64::MAX));
    }
}
