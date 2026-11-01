//! `phantom fleet-status` — one value-free read of every managed secret's
//! posture: name, expiry state, last stored validation result, and
//! rotation-schedule state, with the names whose rotation is overdue
//! collected in one place.
//!
//! Only names and machine-local metadata are read (`list_with_metadata`,
//! `get_validation_metadata`, `backend_name`): no secret value is ever read,
//! no provider is contacted, and nothing is written, so the report is safe to
//! hand to agents and CI. An inventory this process cannot fully see — a
//! locked encrypted-file vault beside an empty OS keychain — is refused
//! through the shared inventory guard instead of reporting as healthy, and a
//! keychain-only listing is marked `partial_keychain_only`.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;

use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::{split_key, DEFAULT_ENV};
use phantom_core::rotation_strategy::strategy_period_secs;
use phantom_core::validator::{ValidationMetadata, DEFAULT_STALE_SECS};
use phantom_vault::metadata::{now_secs, SecretMetadata, Timestamp};
use phantom_vault::rotation_gate::rotation_anchor;

use crate::commands::report_json::{with_schema_pretty, FLEET_STATUS_SCHEMA, STRICT_ISSUES_FOUND};

/// Rotation states reported per secret.
const ROTATION_NONE: &str = "no_schedule";
const ROTATION_WITHIN: &str = "within_period";
const ROTATION_OVERDUE: &str = "overdue";
const ROTATION_UNKNOWN_AGE: &str = "unknown_age";
const ROTATION_SCHEDULE_ERROR: &str = "schedule_error";

/// One secret's posture in the fleet report. Names and metadata only.
#[derive(Debug, Serialize)]
pub struct FleetSecret {
    /// Exact vault entry name (`env/NAME` for scoped secrets).
    pub name: String,
    /// The environment scope parsed from the entry name (`default` for bare names).
    pub environment: String,
    /// The configured service whose `secret_key` this entry stores, if any.
    pub detected_service: Option<String>,
    /// `true` when this secret alone needs operator attention (see `summary.needs_attention`).
    pub attention: bool,
    pub expiry: ExpiryView,
    pub validation: ValidationView,
    pub rotation: RotationView,
}

/// TTL expiry state from vault lifecycle metadata.
#[derive(Debug, Serialize)]
pub struct ExpiryView {
    /// `none` | `valid` | `expiring_soon` | `expired`.
    pub state: &'static str,
    /// The stored expiry instant, when one is set.
    pub expires_at: Option<Timestamp>,
    /// Whole days until expiry; negative when already expired.
    pub days_remaining: Option<i64>,
    /// `true` when the expiry policy demoted this entry (exec/sync refuse it).
    pub read_only: bool,
}

/// The last stored validation result — the record `phantom validate` and the
/// validation scheduler persist. Nothing here re-checks the credential.
#[derive(Debug, Serialize)]
pub struct ValidationView {
    /// `never_checked` | `valid` | `invalid` | `unreachable`.
    pub state: &'static str,
    /// Unix time of the stored check; `null` when never checked.
    pub checked_at: Option<Timestamp>,
    /// `true` when the stored result is older than `DEFAULT_STALE_SECS` (24 h).
    /// Always `false` for a never-checked secret.
    pub stale: bool,
    /// Validator that produced the stored result, when recorded.
    pub validator: Option<String>,
    /// The stored failure reason for `invalid`/`unreachable` results.
    pub failure_reason: Option<String>,
}

/// Rotation-schedule posture, derived the same way the
/// `enforce_rotation_on_access` access gate judges age (the later of the
/// entry's `created_at` and `rotated_at`), but reported for every secret —
/// `enforced` says whether the access gate would actually apply it.
#[derive(Debug, Serialize)]
pub struct RotationView {
    /// `no_schedule` | `within_period` | `overdue` | `unknown_age` | `schedule_error`.
    pub state: &'static str,
    /// Effective schedule label (`weekly`, `every 30 days`, `never`) when one resolves.
    pub schedule: Option<String>,
    /// `true` when `[phantom.secrets.NAME] enforce_rotation_on_access = true`.
    pub enforced: bool,
    /// Unix timestamp the age is measured from, when the entry records one.
    pub anchor: Option<Timestamp>,
    /// Whole days since the anchor; `null` when the age is unknown.
    pub age_days: Option<u64>,
    /// Unix time the current value ages past its schedule; `null` without a
    /// period or a usable anchor.
    pub due_at: Option<Timestamp>,
}

/// Headline counts for the fleet.
#[derive(Debug, Default, Serialize)]
pub struct FleetSummary {
    pub secrets: usize,
    pub expired: usize,
    pub expiring_soon: usize,
    pub read_only: usize,
    pub validation_invalid: usize,
    pub validation_unreachable: usize,
    pub validation_never_checked: usize,
    pub validation_stale: usize,
    pub rotation_overdue: usize,
    pub rotation_unknown_age: usize,
    pub rotation_schedule_errors: usize,
    /// Names in `overdue_rotations`.
    pub overdue_rotations: usize,
    /// Secrets whose `attention` flag is set.
    pub needs_attention: usize,
}

/// The complete `phantom fleet-status --json` document.
#[derive(Debug, Serialize)]
pub struct FleetReport {
    /// `phantom.fleet_status.v1` (also stamped as the `schema` field on output).
    pub kind: &'static str,
    /// Unix time the report was built.
    pub generated_at: Timestamp,
    /// The `--expiring-within` window used for `expiry.state == "expiring_soon"`.
    pub expiring_within_days: u64,
    /// `complete` or `partial_keychain_only` (a locked encrypted-file vault
    /// exists and only the OS keychain was listed — the stderr warning names it).
    pub inventory: &'static str,
    /// `VaultBackend::backend_name` of the opened vault.
    pub vault_backend: String,
    /// One row per vault entry, sorted by name.
    pub secrets: Vec<FleetSecret>,
    /// Names that are expired or past one rotation-schedule period, sorted.
    pub overdue_rotations: Vec<String>,
    /// `true` when any secret needs attention or the inventory is partial —
    /// the condition `--strict` exits 2 on.
    pub needs_attention: bool,
    pub summary: FleetSummary,
}

/// Run `phantom fleet-status [--expiring-within DAYS] [--strict] [--json]`.
///
/// Prints the report, then exits 2 under `--strict` when any secret needs
/// attention or the listing covered only part of the inventory.
pub(crate) fn run(expiring_within_days: u64, strict: bool, json: bool) -> Result<()> {
    let project_dir = crate::util::project_dir()?;
    let config = crate::util::load_project_config(&project_dir)?;
    let vault = crate::util::open_vault(config.local_project_id())?;

    let entries = vault
        .list_with_metadata()
        .context("Failed to read vault metadata")?;

    // A locked file vault beside an empty keychain would otherwise read as an
    // empty — and therefore healthy — fleet.
    let note =
        crate::util::inventory_guard(vault.as_ref(), config.local_project_id(), entries.len())?;
    crate::util::warn_inventory_note(note.as_deref());

    let mut rows = Vec::with_capacity(entries.len());
    for (name, metadata) in entries {
        let validation = vault
            .get_validation_metadata(&name)
            .with_context(|| format!("Failed to read validation metadata for {name}"))?;
        rows.push((name, metadata, validation));
    }

    let report = build_report(
        &config,
        &rows,
        expiring_within_days,
        note.is_some(),
        vault.backend_name(),
        now_secs(),
    );

    if json {
        println!(
            "{}",
            with_schema_pretty(serde_json::to_string_pretty(&report)?, FLEET_STATUS_SCHEMA)?
        );
    } else {
        print_human(&report);
    }

    if strict && report.needs_attention {
        std::process::exit(STRICT_ISSUES_FOUND);
    }
    Ok(())
}

/// Build the report from vault names, lifecycle metadata, and stored
/// validation results. Pure with respect to its inputs: `now` is injected so
/// the classification is deterministic in tests.
fn build_report(
    config: &PhantomConfig,
    rows: &[(String, Option<SecretMetadata>, ValidationMetadata)],
    expiring_within_days: u64,
    partial_inventory: bool,
    vault_backend: &str,
    now: Timestamp,
) -> FleetReport {
    let mut secrets = Vec::with_capacity(rows.len());
    let mut summary = FleetSummary::default();
    let mut overdue_rotations = Vec::new();

    for (name, metadata, validation) in rows {
        let secret = fleet_entry(
            config,
            name,
            metadata.as_ref(),
            validation,
            expiring_within_days,
            now,
        );
        summary.secrets += 1;
        match secret.expiry.state {
            "expired" => summary.expired += 1,
            "expiring_soon" => summary.expiring_soon += 1,
            _ => {}
        }
        summary.read_only += usize::from(secret.expiry.read_only);
        match secret.validation.state {
            "invalid" => summary.validation_invalid += 1,
            "unreachable" => summary.validation_unreachable += 1,
            "never_checked" => summary.validation_never_checked += 1,
            _ => {}
        }
        summary.validation_stale += usize::from(secret.validation.stale);
        match secret.rotation.state {
            ROTATION_OVERDUE => summary.rotation_overdue += 1,
            ROTATION_UNKNOWN_AGE => summary.rotation_unknown_age += 1,
            ROTATION_SCHEDULE_ERROR => summary.rotation_schedule_errors += 1,
            _ => {}
        }
        if secret.expiry.state == "expired" || secret.rotation.state == ROTATION_OVERDUE {
            overdue_rotations.push(secret.name.clone());
        }
        summary.needs_attention += usize::from(secret.attention);
        secrets.push(secret);
    }
    // Deterministic output regardless of the backend's list order.
    secrets.sort_by(|a, b| a.name.cmp(&b.name));
    overdue_rotations.sort();
    summary.overdue_rotations = overdue_rotations.len();

    let needs_attention = summary.needs_attention > 0 || partial_inventory;
    FleetReport {
        kind: FLEET_STATUS_SCHEMA,
        generated_at: now,
        expiring_within_days,
        inventory: if partial_inventory {
            "partial_keychain_only"
        } else {
            "complete"
        },
        vault_backend: vault_backend.to_string(),
        secrets,
        overdue_rotations,
        needs_attention,
        summary,
    }
}

/// One secret's posture. `needs_attention` means an operator should act:
/// expired or read-only under its lifecycle policy, a stored `invalid`
/// validation verdict, or a rotation schedule that is overdue, unmeasurable
/// (`unknown_age`), or unreadable (`schedule_error`).
fn fleet_entry(
    config: &PhantomConfig,
    name: &str,
    metadata: Option<&SecretMetadata>,
    validation: &ValidationMetadata,
    expiring_within_days: u64,
    now: Timestamp,
) -> FleetSecret {
    let (environment, logical) = match split_key(name) {
        Some((env, key)) => (env, key),
        None => (DEFAULT_ENV, name),
    };

    let expires_at = metadata.and_then(|meta| meta.expires_at);
    let days_remaining = metadata.and_then(|meta| meta.days_remaining_at(now));
    let expiry_state = match days_remaining {
        None => "none",
        Some(days) if days < 0 => "expired",
        Some(days) if days <= expiring_within_days as i64 => "expiring_soon",
        Some(_) => "valid",
    };
    let read_only = metadata.is_some_and(|meta| meta.vault_mode.is_read_only());
    let expiry = ExpiryView {
        state: expiry_state,
        expires_at,
        days_remaining,
        read_only,
    };

    // `mark_unreachable` persists `is_valid = false` with an "unreachable: …"
    // reason; that prefix is the only stored distinction from a real verdict.
    let unreachable = validation
        .failure_reason
        .as_deref()
        .is_some_and(|reason| reason.starts_with("unreachable"));
    let validation_state = if validation.never_checked() {
        "never_checked"
    } else if validation.is_valid {
        "valid"
    } else if unreachable {
        "unreachable"
    } else {
        "invalid"
    };
    let validation = ValidationView {
        state: validation_state,
        checked_at: (!validation.never_checked()).then_some(validation.last_check_ts),
        // A checked result is stale past DEFAULT_STALE_SECS; a never-checked
        // secret is not "stale", it is unknown, so keep the flag false there.
        stale: !validation.never_checked()
            && now.saturating_sub(validation.last_check_ts) > DEFAULT_STALE_SECS,
        validator: validation.validator_name.clone(),
        failure_reason: validation.failure_reason.clone(),
    };

    let rotation = rotation_view(config, logical, metadata, now);

    let attention = expiry_state == "expired"
        || read_only
        || validation.state == "invalid"
        || matches!(
            rotation.state,
            ROTATION_OVERDUE | ROTATION_UNKNOWN_AGE | ROTATION_SCHEDULE_ERROR
        );
    FleetSecret {
        name: name.to_string(),
        environment: environment.to_string(),
        detected_service: config
            .services
            .iter()
            .find(|(_, service)| service.secret_key == logical)
            .map(|(service, _)| service.clone()),
        attention,
        expiry,
        validation,
        rotation,
    }
}

/// Resolve the effective rotation schedule for `logical` (per-secret override,
/// then the global `[phantom.rotation_policy]`) and judge the entry's age the
/// same way `check_rotation_enforcement` does: an anchor in the future or no
/// anchor is `unknown_age`, an age of one full period or more is `overdue`.
/// A schedule that does not resolve is `schedule_error` — reported, not
/// silently treated as "no schedule" the way the access gate refuses closed.
fn rotation_view(
    config: &PhantomConfig,
    logical: &str,
    metadata: Option<&SecretMetadata>,
    now: Timestamp,
) -> RotationView {
    let enforced = config
        .phantom
        .secrets
        .get(logical)
        .is_some_and(|secret| secret.enforce_rotation_on_access);
    let anchor = rotation_anchor(metadata);
    let age_days = anchor
        .filter(|anchor| *anchor <= now)
        .map(|anchor| (now - anchor) / 86_400);

    let schedule = match config.get_rotation_schedule(logical) {
        Ok(schedule) => schedule,
        Err(_) => {
            return RotationView {
                state: ROTATION_SCHEDULE_ERROR,
                schedule: None,
                enforced,
                anchor,
                age_days,
                due_at: None,
            }
        }
    };
    let Some(period) = schedule
        .as_ref()
        .and_then(|schedule| strategy_period_secs(&schedule.strategy))
    else {
        return RotationView {
            state: ROTATION_NONE,
            schedule: schedule.map(|schedule| schedule.strategy.to_label()),
            enforced,
            anchor,
            age_days,
            due_at: None,
        };
    };
    let label = schedule.map(|schedule| schedule.strategy.to_label());
    let Some(anchor) = anchor.filter(|anchor| *anchor <= now) else {
        return RotationView {
            state: ROTATION_UNKNOWN_AGE,
            schedule: label,
            enforced,
            anchor,
            age_days,
            due_at: None,
        };
    };
    let due_at = anchor + period;
    let state = if now - anchor >= period {
        ROTATION_OVERDUE
    } else {
        ROTATION_WITHIN
    };
    RotationView {
        state,
        schedule: label,
        enforced,
        anchor: Some(anchor),
        age_days,
        due_at: Some(due_at),
    }
}

/// Print the human-readable fleet table.
fn print_human(report: &FleetReport) {
    println!("{}", "Phantom Fleet Status".bold());
    println!(
        "  Vault: {} · Inventory: {} · {} secret(s)\n",
        report.vault_backend, report.inventory, report.summary.secrets
    );

    if report.secrets.is_empty() {
        println!(
            "{} No secrets in the vault. Store one from a trusted terminal with `phantom add`.",
            "ok".green().bold()
        );
        return;
    }

    println!(
        "  {:<26} {:<8} {:<14} {:<20} ROTATION",
        "NAME", "ENV", "EXPIRY", "VALIDATION"
    );
    println!("  {}", "-".repeat(92));
    for secret in &report.secrets {
        let expiry = match secret.expiry.state {
            "expired" => "EXPIRED".red().bold().to_string(),
            "expiring_soon" => {
                format!("{}d left", secret.expiry.days_remaining.unwrap_or_default())
                    .yellow()
                    .to_string()
            }
            "valid" => format!("{}d left", secret.expiry.days_remaining.unwrap_or_default()),
            _ => "-".to_string(),
        };
        let expiry = if secret.expiry.read_only {
            format!("{expiry} {}", "[read-only]".red())
        } else {
            expiry
        };
        let validation = match secret.validation.state {
            "invalid" => "INVALID".red().bold().to_string(),
            "unreachable" => "unreachable".yellow().to_string(),
            "valid" if secret.validation.stale => "valid (stale)".yellow().to_string(),
            "valid" => "valid".to_string(),
            _ => "never checked".dimmed().to_string(),
        };
        let rotation = match secret.rotation.state {
            ROTATION_OVERDUE => "OVERDUE".red().bold().to_string(),
            ROTATION_UNKNOWN_AGE => "unknown age".yellow().to_string(),
            ROTATION_SCHEDULE_ERROR => "schedule error".red().to_string(),
            ROTATION_WITHIN => format!(
                "due in {}d",
                rotation_days_left(secret, report.generated_at)
            ),
            _ => "-".to_string(),
        };
        println!(
            "  {:<26} {:<8} {:<14} {:<20} {}",
            secret.name.bold(),
            secret.environment,
            expiry,
            validation,
            rotation
        );
    }

    println!();
    let summary = &report.summary;
    if report.needs_attention {
        println!(
            "{} {} secret(s) need attention: {} expired · {} invalid · {} overdue rotation(s){}",
            "!".red().bold(),
            summary.needs_attention,
            summary.expired,
            summary.validation_invalid,
            summary.overdue_rotations,
            if report.inventory != "complete" {
                " · inventory is partial"
            } else {
                ""
            }
        );
        if !report.overdue_rotations.is_empty() {
            println!(
                "  Overdue rotations: {}",
                report.overdue_rotations.join(", ")
            );
        }
    } else {
        println!(
            "{} {} secret(s): none need attention.",
            "ok".green().bold(),
            summary.secrets
        );
    }
}

/// Whole days until `due_at` for a `within_period` row (0 when due today).
fn rotation_days_left(secret: &FleetSecret, now: Timestamp) -> u64 {
    secret
        .rotation
        .due_at
        .map(|due| due.saturating_sub(now) / 86_400)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::config::SecretOverride;
    use phantom_vault::metadata::VaultMode;

    const DAY: u64 = 86_400;
    const NOW: Timestamp = 1_800_000_000;

    fn config_with(entries: &[(&str, Option<&str>, bool)]) -> PhantomConfig {
        let mut config = PhantomConfig::new_with_defaults("fleet-test".to_string());
        for (name, rotate_every, enforce) in entries {
            config.phantom.secrets.insert(
                name.to_string(),
                SecretOverride {
                    rotate_every: rotate_every.map(str::to_string),
                    enforce_rotation_on_access: *enforce,
                    ..SecretOverride::default()
                },
            );
        }
        config
    }

    fn meta(created_at: Option<u64>, expires_at: Option<u64>) -> Option<SecretMetadata> {
        Some(SecretMetadata {
            created_at,
            expires_at,
            ..SecretMetadata::default()
        })
    }

    fn checked(valid: bool, checked_at: u64) -> ValidationMetadata {
        ValidationMetadata {
            last_check_ts: checked_at,
            is_valid: valid,
            failure_reason: (!valid).then(|| "fixture failure reason".to_string()),
            validator_name: Some("fixture-validator".to_string()),
        }
    }

    #[test]
    fn expiry_states_classify_against_the_window() {
        let config = config_with(&[]);
        let never = ValidationMetadata::default();
        let entry = |expires_at| {
            fleet_entry(
                &config,
                "KEY",
                meta(Some(NOW - DAY), expires_at).as_ref(),
                &never,
                7,
                NOW,
            )
        };
        assert_eq!(entry(None).expiry.state, "none");
        assert_eq!(entry(Some(NOW - 1)).expiry.state, "expired");
        assert_eq!(entry(Some(NOW + 3 * DAY)).expiry.state, "expiring_soon");
        assert_eq!(entry(Some(NOW + 30 * DAY)).expiry.state, "valid");
        assert_eq!(entry(Some(NOW + 30 * DAY)).expiry.days_remaining, Some(30));
    }

    #[test]
    fn validation_states_read_the_stored_record() {
        let config = config_with(&[]);
        let meta = meta(Some(NOW - DAY), None);
        let entry = |validation: ValidationMetadata| {
            fleet_entry(&config, "KEY", meta.as_ref(), &validation, 7, NOW)
        };
        assert_eq!(
            entry(ValidationMetadata::default()).validation.state,
            "never_checked"
        );
        assert_eq!(entry(checked(true, NOW)).validation.state, "valid");
        assert_eq!(entry(checked(false, NOW)).validation.state, "invalid");
        assert!(entry(checked(false, NOW)).attention);

        let unreachable = ValidationMetadata {
            last_check_ts: NOW,
            is_valid: false,
            failure_reason: Some("unreachable: fixture timeout".to_string()),
            validator_name: None,
        };
        assert_eq!(entry(unreachable).validation.state, "unreachable");

        // A check older than 24 h is stale; a fresh one is not; never-checked
        // reports `stale: false` (it is unknown, not stale).
        assert!(
            entry(checked(true, NOW - DEFAULT_STALE_SECS - 1))
                .validation
                .stale
        );
        assert!(
            !entry(checked(true, NOW - DEFAULT_STALE_SECS))
                .validation
                .stale
        );
        assert!(!entry(ValidationMetadata::default()).validation.stale);
        assert_eq!(
            entry(ValidationMetadata::default()).validation.checked_at,
            None
        );
    }

    #[test]
    fn rotation_state_follows_the_access_gate() {
        let config = config_with(&[("KEY", Some("30d"), true), ("FREE", Some("90d"), false)]);
        let never = ValidationMetadata::default();
        let entry = |name: &str, created_at: Option<u64>| {
            fleet_entry(
                &config,
                name,
                meta(created_at, None).as_ref(),
                &never,
                7,
                NOW,
            )
        };
        // 45 days into a 30-day schedule: overdue whether or not it is enforced.
        assert_eq!(entry("KEY", Some(NOW - 45 * DAY)).rotation.state, "overdue");
        assert_eq!(
            entry("FREE", Some(NOW - 45 * DAY)).rotation.state,
            "within_period"
        );
        assert!(entry("KEY", Some(NOW - 45 * DAY)).rotation.enforced);
        assert!(!entry("FREE", Some(NOW - DAY)).rotation.enforced);
        // No anchor and a future anchor are both unknown_age; no schedule is
        // no_schedule; a malformed rotate_every is schedule_error.
        assert_eq!(entry("KEY", None).rotation.state, "unknown_age");
        assert_eq!(entry("KEY", Some(NOW + DAY)).rotation.state, "unknown_age");
        assert_eq!(
            entry("OTHER", Some(NOW - DAY)).rotation.state,
            "no_schedule"
        );

        let bad = config_with(&[("BAD", Some("soon"), false)]);
        let bad_meta = meta(Some(NOW - DAY), None);
        let entry = fleet_entry(&bad, "BAD", bad_meta.as_ref(), &never, 7, NOW);
        assert_eq!(entry.rotation.state, "schedule_error");
        assert!(entry.attention);
    }

    #[test]
    fn env_scoped_names_resolve_policy_by_logical_name() {
        let config = config_with(&[("API_KEY", Some("30d"), true)]);
        let never = ValidationMetadata::default();
        let scoped = meta(Some(NOW - 45 * DAY), None);
        let entry = fleet_entry(&config, "staging/API_KEY", scoped.as_ref(), &never, 7, NOW);
        assert_eq!(entry.environment, "staging");
        assert_eq!(entry.rotation.state, "overdue");
        assert!(entry.rotation.enforced);
    }

    #[test]
    fn report_collects_overdue_rotations_and_needs_attention() {
        let config = config_with(&[("STALE", Some("30d"), false)]);
        let never = ValidationMetadata::default();
        let rows = vec![
            (
                "STALE".to_string(),
                meta(Some(NOW - 45 * DAY), None).unwrap(),
                never.clone(),
            ),
            (
                "EXPIRED".to_string(),
                SecretMetadata {
                    created_at: Some(NOW - DAY),
                    expires_at: Some(NOW - 1),
                    vault_mode: VaultMode::ReadOnly,
                    ..SecretMetadata::default()
                },
                never.clone(),
            ),
            (
                "FRESH".to_string(),
                meta(Some(NOW - DAY), Some(NOW + 90 * DAY)).unwrap(),
                checked(true, NOW),
            ),
        ]
        .into_iter()
        .map(|(name, meta, validation)| (name, Some(meta), validation))
        .collect::<Vec<_>>();

        let report = build_report(&config, &rows, 7, false, "fixture", NOW);
        assert_eq!(report.summary.secrets, 3);
        assert_eq!(report.overdue_rotations, ["EXPIRED", "STALE"]);
        assert_eq!(report.summary.overdue_rotations, 2);
        assert_eq!(report.summary.needs_attention, 2);
        assert!(report.needs_attention);
        assert_eq!(report.inventory, "complete");

        let partial = build_report(&config, &rows, 7, true, "fixture", NOW);
        assert_eq!(partial.inventory, "partial_keychain_only");
        assert!(partial.needs_attention);

        // A clean fleet under a complete inventory needs no attention.
        let clean = build_report(&config, &rows[2..], 7, false, "fixture", NOW);
        assert!(!clean.needs_attention);
        assert_eq!(clean.summary.needs_attention, 0);
    }

    #[test]
    fn serialized_report_contains_names_and_metadata_never_values() {
        let config = config_with(&[]);
        let rows = vec![(
            "FIXTURE_KEY".to_string(),
            meta(Some(NOW - DAY), Some(NOW + 5 * DAY)),
            checked(true, NOW),
        )];
        let report = build_report(&config, &rows, 7, false, "fixture", NOW);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("FIXTURE_KEY"));
        assert!(json.contains("expiring_soon"));
        assert!(!json.contains("phm_"));
        assert!(!json.contains("value"));
    }

    #[test]
    fn source_never_reads_a_secret_value() {
        // The report is value-free by construction: it must never call the
        // retrieval surface (`.retrieve`, `exists` is listing-only and unused).
        // Scan only the shipped code: this test names the needles itself.
        let source = include_str!("fleet_status.rs")
            .split("\n#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            ".retrieve(",
            ".retrieve_for_injection(",
            "compare_and_swap(",
        ] {
            assert!(
                !source.contains(forbidden),
                "fleet_status.rs must not read or write secret values ({forbidden})"
            );
        }
    }
}

#[cfg(all(test, unix))]
mod locked_vault_tests {
    use crate::util::test_seam::{empty_keychain, keychain_with_one, LockedProject};

    /// An empty OS keychain beside a locked encrypted-file vault must never
    /// report an empty — and therefore healthy — fleet.
    #[test]
    fn fleet_status_refuses_a_locked_file_vault() {
        let _project = LockedProject::new(empty_keychain);
        for json in [false, true] {
            let error = super::run(7, false, json).unwrap_err();
            assert!(error.to_string().starts_with("Vault locked:"), "{error:#}");
        }
    }

    /// A keychain-only view beside a locked file vault still reports (with
    /// the partial-inventory warning) — and `keychain_with_one` panics if any
    /// value is ever read, proving the report stays metadata-only.
    #[test]
    fn fleet_status_reports_a_keychain_only_view_without_reading_values() {
        let _project = LockedProject::new(keychain_with_one);
        super::run(7, false, true).expect("a keychain-only listing still reports");
    }
}
