//! Integration tests for the automated secret validation scheduler CLI:
//!
//! 1. `validate_all_mixed_results` — run pipeline with mixed valid/invalid results,
//!    check report counts and the `has_invalid` exit-1 signal.
//! 2. `watch_mode_detects_invalid_and_updates_report` — simulate one watch-mode
//!    tick: invalid secret updates vault metadata + a JSON report on disk has
//!    `has_invalid=true`.
//! 3. `per_secret_schedule_daily_not_rechecked_if_fresh` — daily-scheduled secret
//!    whose `last_check_ts` is < 24 h ago is skipped by
//!    `ValidationScheduleConfig::is_due`.

mod common;

use phantom_core::config::ValidationScheduleConfig;
use phantom_core::validator::{
    run_validation_pipeline, SecretValidator, ValidationMetadata, ValidationResult,
    ValidationStatus,
};
use phantom_vault::VaultBackend;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn zs(s: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(s.to_string())
}

struct MockValidator {
    name: String,
    pattern: String,
    result: ValidationResult,
}

impl SecretValidator for MockValidator {
    fn name(&self) -> &str {
        &self.name
    }
    fn matches(&self, key: &str) -> bool {
        key.to_uppercase().contains(&self.pattern.to_uppercase())
    }
    fn validate(
        &self,
        _key: &str,
        _value: &zeroize::Zeroizing<String>,
        _timeout: Duration,
    ) -> ValidationResult {
        self.result.clone()
    }
}

fn mock_valid(name: &str, pattern: &str) -> Box<dyn SecretValidator> {
    Box::new(MockValidator {
        name: name.to_string(),
        pattern: pattern.to_string(),
        result: ValidationResult::Valid,
    })
}

fn mock_invalid(name: &str, pattern: &str, reason: &str) -> Box<dyn SecretValidator> {
    Box::new(MockValidator {
        name: name.to_string(),
        pattern: pattern.to_string(),
        result: ValidationResult::Invalid {
            reason: reason.to_string(),
        },
    })
}

fn mock_unreachable(name: &str, pattern: &str, reason: &str) -> Box<dyn SecretValidator> {
    Box::new(MockValidator {
        name: name.to_string(),
        pattern: pattern.to_string(),
        result: ValidationResult::Unreachable {
            reason: reason.to_string(),
        },
    })
}

/// Minimal watch-report written to disk (mirrors WatchReport in validate.rs).
#[derive(Debug, Serialize, Deserialize)]
struct WatchReport {
    updated_at: u64,
    has_invalid: bool,
    invalid_count: usize,
    valid_count: usize,
    total: usize,
}

// ── Test 1: mixed valid/invalid pipeline results ──────────────────────────────

/// Integration test 1: run the full validation pipeline with a mix of valid,
/// invalid, unreachable, and unchecked secrets.  Assert the report counts are
/// correct and that `has_invalid` (exit-1 signal) is true.
#[test]
fn validate_all_mixed_results_report_counts_and_exit_signal() {
    let secrets = vec![
        ("OPENAI_API_KEY".to_string(), zs("sk-valid")),
        ("STRIPE_SECRET_KEY".to_string(), zs("sk_revoked")),
        ("GITHUB_TOKEN".to_string(), zs("ghp_unreachable")),
        ("NO_VALIDATOR_KEY".to_string(), zs("abc123")),
    ];

    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_valid("openai", "OPENAI"),
        mock_invalid("stripe", "STRIPE", "401 — key revoked"),
        mock_unreachable("github", "GITHUB", "connection refused"),
    ];

    let report = run_validation_pipeline(secrets, &validators, 4, Duration::from_secs(5));

    assert_eq!(report.total, 4, "total should include all 4 secrets");
    assert_eq!(report.valid, 1, "only OPENAI should be valid");
    assert_eq!(report.invalid, 1, "only STRIPE should be invalid");
    assert_eq!(report.unreachable, 1, "only GITHUB should be unreachable");
    assert_eq!(report.not_checked, 1, "NO_VALIDATOR_KEY has no validator");

    let invalid_entries = report.invalid_entries();
    assert_eq!(invalid_entries.len(), 1);
    assert_eq!(invalid_entries[0].name, "STRIPE_SECRET_KEY");
    assert!(
        invalid_entries[0]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("401"),
        "reason should mention 401"
    );

    let unreachable_entries = report.unreachable_entries();
    assert_eq!(unreachable_entries.len(), 1);
    assert_eq!(unreachable_entries[0].name, "GITHUB_TOKEN");

    // The CLI exits 1 when report.invalid > 0.
    let has_invalid = report.invalid > 0;
    assert!(
        has_invalid,
        "has_invalid should be true for a mixed-result run"
    );

    // JSON serialisation must not leak any secret values.
    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    assert!(
        !json.contains("sk-valid"),
        "JSON must not contain secret values"
    );
    assert!(
        !json.contains("sk_revoked"),
        "JSON must not contain secret values"
    );
    assert!(
        !json.contains("ghp_unreachable"),
        "JSON must not contain secret values"
    );
}

// ── Test 2: watch mode detects fresh invalid secret and updates report ────────

/// Integration test 2: simulate one watch-mode tick.  After validation, invalid
/// secrets are persisted in the vault and the watch report written to disk has
/// `has_invalid = true`.
#[test]
fn watch_mode_detects_fresh_invalid_secret_and_updates_report() {
    let dir = common::canonical_tempdir();
    let vault = phantom_vault::file::FileVault::new(
        dir.path(),
        "test-watch-invalid",
        "test-pass".to_string(),
    )
    .unwrap();

    vault.store("OPENAI_API_KEY", "sk-good").unwrap();
    vault.store("STRIPE_SECRET_KEY", "sk_revoked").unwrap();

    // Initially neither has been validated.
    assert!(vault
        .get_validation_metadata("OPENAI_API_KEY")
        .unwrap()
        .never_checked());
    assert!(vault
        .get_validation_metadata("STRIPE_SECRET_KEY")
        .unwrap()
        .never_checked());

    // Simulate one watch tick: run pipeline.
    let secrets = vec![
        ("OPENAI_API_KEY".to_string(), zs("sk-good")),
        ("STRIPE_SECRET_KEY".to_string(), zs("sk_revoked")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_valid("openai", "OPENAI"),
        mock_invalid("stripe", "STRIPE", "401 — key revoked"),
    ];
    let report = run_validation_pipeline(secrets, &validators, 4, Duration::from_secs(5));

    // Persist ValidationMetadata into vault (mirrors watch_loop behaviour).
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
        vault.set_validation_metadata(&entry.name, meta).unwrap();
    }

    // Verify vault metadata was updated correctly.
    let openai_meta = vault.get_validation_metadata("OPENAI_API_KEY").unwrap();
    assert!(openai_meta.is_valid, "OPENAI should be marked valid");
    assert!(!openai_meta.never_checked());

    let stripe_meta = vault.get_validation_metadata("STRIPE_SECRET_KEY").unwrap();
    assert!(!stripe_meta.is_valid, "STRIPE should be marked invalid");
    assert!(
        stripe_meta
            .failure_reason
            .as_deref()
            .unwrap_or("")
            .contains("401"),
        "failure_reason should contain 401, got: {:?}",
        stripe_meta.failure_reason
    );

    // Write the WatchReport JSON to disk (mirrors the watch-loop file write).
    let report_file = dir.path().join("validation-report.json");
    let watch_report = WatchReport {
        updated_at: now_secs(),
        has_invalid: report.invalid > 0,
        invalid_count: report.invalid,
        valid_count: report.valid,
        total: report.total,
    };
    let json_bytes = serde_json::to_vec_pretty(&watch_report).unwrap();
    phantom_core::fs::atomic_write(&report_file, &json_bytes).unwrap();

    // Read back and assert.
    let raw = std::fs::read_to_string(&report_file).unwrap();
    let read_back: WatchReport = serde_json::from_str(&raw).unwrap();

    assert!(
        read_back.has_invalid,
        "has_invalid should be true in the written report"
    );
    assert_eq!(read_back.invalid_count, 1);
    assert_eq!(read_back.valid_count, 1);
    assert_eq!(read_back.total, 2);
    assert!(read_back.updated_at > 0, "updated_at should be non-zero");
}

// ── Test 3: per-secret schedule respected — daily not re-checked < 24 h ──────

/// Integration test 3: `ValidationScheduleConfig::is_due` must return `false`
/// for a daily-scheduled secret whose `last_check_ts` is < 24 h ago, and
/// `true` when more than 24 h has elapsed (or never checked).
#[test]
fn per_secret_schedule_daily_not_rechecked_if_fresh() {
    let daily_cfg = ValidationScheduleConfig {
        enabled: true,
        schedule: "daily".to_string(),
        timeout_secs: 30,
        ..Default::default()
    };

    // Never checked (ts=0) — always due.
    assert!(
        daily_cfg.is_due(0),
        "never-checked secret should always be due"
    );

    // Checked 23 h 59 m ago — NOT due (< 24 h elapsed).
    let almost_day_ago = now_secs().saturating_sub(23 * 3600 + 59 * 60);
    assert!(
        !daily_cfg.is_due(almost_day_ago),
        "secret checked < 24h ago should not be due on daily schedule"
    );

    // Checked exactly 24 h ago — due.
    let exactly_day_ago = now_secs().saturating_sub(86_400);
    assert!(
        daily_cfg.is_due(exactly_day_ago),
        "secret checked exactly 24h ago should be due on daily schedule"
    );

    // Checked 2 days ago — definitely due.
    let two_days_ago = now_secs().saturating_sub(2 * 86_400);
    assert!(
        daily_cfg.is_due(two_days_ago),
        "secret checked 2 days ago should be due on daily schedule"
    );

    // Weekly schedule: 6-day-old check is NOT due yet.
    let weekly_cfg = ValidationScheduleConfig {
        enabled: true,
        schedule: "weekly".to_string(),
        timeout_secs: 30,
        ..Default::default()
    };
    let six_days_ago = now_secs().saturating_sub(6 * 86_400);
    assert!(
        !weekly_cfg.is_due(six_days_ago),
        "secret checked 6 days ago should not be due on weekly schedule"
    );

    // Weekly schedule: 7-day-old check IS due.
    let seven_days_ago = now_secs().saturating_sub(7 * 86_400);
    assert!(
        weekly_cfg.is_due(seven_days_ago),
        "secret checked 7 days ago should be due on weekly schedule"
    );

    // Schedule = "never": never due regardless of last_check_ts.
    let never_cfg = ValidationScheduleConfig {
        enabled: true,
        schedule: "never".to_string(),
        timeout_secs: 30,
        ..Default::default()
    };
    assert!(
        !never_cfg.is_due(0),
        "never schedule: ts=0 should not be due"
    );
    assert!(
        !never_cfg.is_due(1),
        "never schedule: old ts should not be due"
    );

    // Disabled: never due regardless of schedule.
    let disabled_cfg = ValidationScheduleConfig {
        enabled: false,
        schedule: "daily".to_string(),
        timeout_secs: 30,
        ..Default::default()
    };
    assert!(
        !disabled_cfg.is_due(0),
        "disabled validation: ts=0 should not be due"
    );
    assert!(
        !disabled_cfg.is_due(1),
        "disabled validation: old ts should not be due"
    );
}

// ── Test 4: ValidationMetadata round-trips through FileVault after pipeline ───

/// Extra test: pipeline run + metadata persistence + vault reload confirms that
/// `set_validation_metadata` / `get_validation_metadata` survive a round-trip.
#[test]
fn pipeline_metadata_persisted_in_file_vault_after_run() {
    let dir = common::canonical_tempdir();
    let vault =
        phantom_vault::file::FileVault::new(dir.path(), "test-meta-roundtrip", "pass".to_string())
            .unwrap();

    vault.store("ANTHROPIC_API_KEY", "sk-ant-test").unwrap();
    vault.store("GITHUB_TOKEN", "ghp_test").unwrap();

    let secrets = vec![
        ("ANTHROPIC_API_KEY".to_string(), zs("sk-ant-test")),
        ("GITHUB_TOKEN".to_string(), zs("ghp_test")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_valid("anthropic", "ANTHROPIC"),
        mock_unreachable("github", "GITHUB", "timeout"),
    ];
    let report = run_validation_pipeline(secrets, &validators, 2, Duration::from_secs(5));

    for entry in &report.entries {
        let meta = match entry.status {
            ValidationStatus::Valid => ValidationMetadata::mark_valid(&entry.validator),
            ValidationStatus::Unreachable => ValidationMetadata::mark_unreachable(
                &entry.validator,
                entry.reason.as_deref().unwrap_or(""),
            ),
            _ => continue,
        };
        vault.set_validation_metadata(&entry.name, meta).unwrap();
    }

    // Reload vault to confirm on-disk persistence.
    let vault2 =
        phantom_vault::file::FileVault::new(dir.path(), "test-meta-roundtrip", "pass".to_string())
            .unwrap();

    let anthropic_meta = vault2.get_validation_metadata("ANTHROPIC_API_KEY").unwrap();
    assert!(
        anthropic_meta.is_valid,
        "ANTHROPIC should be valid after persist+reload"
    );
    assert_eq!(anthropic_meta.validator_name.as_deref(), Some("anthropic"));

    let github_meta = vault2.get_validation_metadata("GITHUB_TOKEN").unwrap();
    assert!(
        !github_meta.is_valid,
        "GITHUB should be invalid (unreachable) after persist+reload"
    );
    assert!(
        github_meta
            .failure_reason
            .as_deref()
            .unwrap_or("")
            .contains("unreachable"),
        "failure_reason should contain 'unreachable', got: {:?}",
        github_meta.failure_reason
    );
}
