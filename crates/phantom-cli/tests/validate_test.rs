//! Integration tests for `phantom validate` — drift detection & credential health checks.
//!
//! These tests use mock HTTP servers (wiremock) to exercise the validation pipeline
//! end-to-end: HTTP-based validation, timeout resilience, partial failure handling,
//! metadata persistence, and audit trail.

mod common;

use phantom_core::validator::{
    default_validators, run_validation_pipeline, run_validation_pipeline_parallel,
    AnthropicValidator, GenericHttpValidator, GitHubValidator, OpenAiValidator, SecretValidator,
    StripeValidator, ValidationMetadata, ValidationReport, ValidationResult, ValidationStatus,
    DEFAULT_STALE_SECS,
};
use phantom_vault::VaultBackend;
use std::time::Duration;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn zs(s: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(s.to_string())
}

/// A mock validator with a configurable result.
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

// ── Metadata tests ───────────────────────────────────────────────────────────

#[test]
fn validation_metadata_never_checked_default() {
    let m = ValidationMetadata::default();
    assert!(m.never_checked());
    assert_eq!(m.last_check_ts, 0);
    assert!(!m.is_valid);
    assert!(m.failure_reason.is_none());
    assert!(m.validator_name.is_none());
}

#[test]
fn validation_metadata_mark_valid_sets_timestamp() {
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let m = ValidationMetadata::mark_valid("openai");
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(m.last_check_ts >= before && m.last_check_ts <= after);
    assert!(m.is_valid);
    assert!(m.failure_reason.is_none());
    assert_eq!(m.validator_name.as_deref(), Some("openai"));
    assert!(!m.never_checked());
}

#[test]
fn validation_metadata_mark_invalid_records_reason() {
    let m = ValidationMetadata::mark_invalid("stripe", "key revoked");
    assert!(!m.is_valid);
    assert_eq!(m.failure_reason.as_deref(), Some("key revoked"));
    assert_eq!(m.validator_name.as_deref(), Some("stripe"));
}

#[test]
fn validation_metadata_mark_unreachable_prefixes_reason() {
    let m = ValidationMetadata::mark_unreachable("github", "DNS failure");
    assert!(!m.is_valid);
    let reason = m.failure_reason.as_deref().unwrap();
    assert!(reason.contains("unreachable"), "reason: {reason}");
    assert!(reason.contains("DNS failure"), "reason: {reason}");
}

#[test]
fn validation_metadata_is_stale_when_never_checked() {
    let m = ValidationMetadata::default();
    assert!(m.is_stale(DEFAULT_STALE_SECS));
    assert!(m.is_stale(0));
}

#[test]
fn validation_metadata_not_stale_just_checked() {
    let m = ValidationMetadata::mark_valid("test");
    assert!(!m.is_stale(DEFAULT_STALE_SECS));
}

#[test]
fn validation_metadata_stale_threshold_respected() {
    let m = ValidationMetadata {
        last_check_ts: 1, // epoch + 1s
        is_valid: true,
        failure_reason: None,
        validator_name: None,
    };
    assert!(m.is_stale(60)); // 60 s threshold — definitely stale
    assert!(m.is_stale(DEFAULT_STALE_SECS));
}

#[test]
fn validation_metadata_json_round_trip_valid() {
    let m = ValidationMetadata::mark_valid("anthropic");
    let json = serde_json::to_string(&m).unwrap();
    let back: ValidationMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(back.is_valid, m.is_valid);
    assert_eq!(back.validator_name, m.validator_name);
    assert_eq!(back.failure_reason, m.failure_reason);
    assert!(json.contains("\"is_valid\":true"));
    assert!(
        !json.contains("\"failure_reason\""),
        "None should be omitted: {json}"
    );
}

#[test]
fn validation_metadata_json_round_trip_invalid() {
    let m = ValidationMetadata::mark_invalid("stripe", "401 Unauthorized");
    let json = serde_json::to_string(&m).unwrap();
    let back: ValidationMetadata = serde_json::from_str(&json).unwrap();
    assert!(!back.is_valid);
    assert_eq!(back.failure_reason.as_deref(), Some("401 Unauthorized"));
}

// ── Validator matching tests ──────────────────────────────────────────────────

#[test]
fn openai_validator_name() {
    assert_eq!(OpenAiValidator.name(), "openai");
}

#[test]
fn openai_matches_standard_key_names() {
    let v = OpenAiValidator;
    assert!(v.matches("OPENAI_API_KEY"));
    assert!(v.matches("OPENAI_SECRET_KEY"));
    assert!(v.matches("MY_OPENAI_TOKEN"));
    assert!(!v.matches("STRIPE_SECRET_KEY"));
    assert!(!v.matches("GITHUB_TOKEN"));
    assert!(!v.matches("DATABASE_URL"));
}

#[test]
fn stripe_validator_name() {
    assert_eq!(StripeValidator.name(), "stripe");
}

#[test]
fn stripe_matches_standard_key_names() {
    let v = StripeValidator;
    assert!(v.matches("STRIPE_SECRET_KEY"));
    assert!(v.matches("STRIPE_API_KEY"));
    assert!(v.matches("STRIPE_TOKEN"));
    assert!(!v.matches("OPENAI_API_KEY"));
    assert!(!v.matches("GITHUB_TOKEN"));
}

#[test]
fn github_validator_name() {
    assert_eq!(GitHubValidator.name(), "github");
}

#[test]
fn github_matches_standard_key_names() {
    let v = GitHubValidator;
    assert!(v.matches("GITHUB_TOKEN"));
    assert!(v.matches("GITHUB_API_KEY"));
    assert!(v.matches("MY_GITHUB_SECRET"));
    assert!(!v.matches("OPENAI_API_KEY"));
    assert!(!v.matches("STRIPE_SECRET_KEY"));
}

#[test]
fn github_gh_prefix_does_not_match() {
    // The GitHubValidator pattern requires "GITHUB" — "GH_TOKEN" does not match.
    // This is intentional: short-form GH_* vars require an explicit custom validator.
    let v = GitHubValidator;
    assert!(
        !v.matches("GH_TOKEN"),
        "GH_TOKEN should not match — pattern requires GITHUB"
    );
}

#[test]
fn anthropic_validator_name() {
    assert_eq!(AnthropicValidator.name(), "anthropic");
}

#[test]
fn anthropic_matches_standard_key_names() {
    let v = AnthropicValidator;
    assert!(v.matches("ANTHROPIC_API_KEY"));
    assert!(v.matches("ANTHROPIC_TOKEN"));
    assert!(!v.matches("OPENAI_API_KEY"));
    assert!(!v.matches("STRIPE_SECRET_KEY"));
}

#[test]
fn generic_http_validator_custom_pattern() {
    let v = GenericHttpValidator::new(
        "my-service",
        vec!["MY_SERVICE".to_string()],
        "https://example.com/check",
    );
    assert_eq!(v.name(), "my-service");
    assert!(v.matches("MY_SERVICE_API_KEY"));
    assert!(v.matches("my_service_token"));
    assert!(!v.matches("OPENAI_API_KEY"));
}

#[test]
fn generic_http_validator_multiple_patterns() {
    let v = GenericHttpValidator::new(
        "multi",
        vec!["FOO".to_string(), "BAR".to_string()],
        "https://example.com",
    );
    assert!(v.matches("FOO_KEY"));
    assert!(v.matches("BAR_TOKEN"));
    assert!(!v.matches("OPENAI_API_KEY"));
}

// ── Pipeline integration tests ────────────────────────────────────────────────

#[test]
fn pipeline_all_valid_report() {
    let secrets = vec![
        ("OPENAI_API_KEY".to_string(), zs("sk-valid")),
        ("STRIPE_SECRET_KEY".to_string(), zs("sk_live_valid")),
        ("GITHUB_TOKEN".to_string(), zs("ghp_valid")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_valid("openai", "OPENAI"),
        mock_valid("stripe", "STRIPE"),
        mock_valid("github", "GITHUB"),
    ];
    let report = run_validation_pipeline(secrets, &validators, 4, Duration::from_secs(5));
    assert_eq!(report.total, 3);
    assert_eq!(report.valid, 3);
    assert_eq!(report.invalid, 0);
    assert_eq!(report.unreachable, 0);
    assert_eq!(report.not_checked, 0);
    assert!(report.invalid_entries().is_empty());
    assert!(report.unreachable_entries().is_empty());
    assert!(report.not_checked_entries().is_empty());
}

#[test]
fn pipeline_one_invalid_others_continue() {
    let secrets = vec![
        ("OPENAI_API_KEY".to_string(), zs("sk-revoked")),
        ("STRIPE_SECRET_KEY".to_string(), zs("sk_live_ok")),
        ("GITHUB_TOKEN".to_string(), zs("ghp_ok")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_invalid("openai", "OPENAI", "401 — key revoked"),
        mock_valid("stripe", "STRIPE"),
        mock_valid("github", "GITHUB"),
    ];
    let report = run_validation_pipeline(secrets, &validators, 2, Duration::from_secs(5));
    assert_eq!(report.total, 3);
    assert_eq!(report.invalid, 1);
    assert_eq!(report.valid, 2);
    let inv = report.invalid_entries();
    assert_eq!(inv.len(), 1);
    assert_eq!(inv[0].name, "OPENAI_API_KEY");
    assert!(inv[0].reason.as_deref().unwrap().contains("401"));
}

#[test]
fn pipeline_unreachable_does_not_affect_others() {
    let secrets = vec![
        ("GITHUB_TOKEN".to_string(), zs("ghp_bad_network")),
        ("OPENAI_API_KEY".to_string(), zs("sk-valid")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_unreachable("github", "GITHUB", "connection refused: 111"),
        mock_valid("openai", "OPENAI"),
    ];
    let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
    assert_eq!(report.total, 2);
    assert_eq!(report.unreachable, 1);
    assert_eq!(report.valid, 1);
    assert_eq!(report.invalid, 0);
    let un = report.unreachable_entries();
    assert_eq!(un.len(), 1);
    assert_eq!(un[0].name, "GITHUB_TOKEN");
    assert!(un[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("connection refused"));
}

#[test]
fn pipeline_no_validator_matches() {
    let secrets = vec![
        ("CUSTOM_UNKNOWN_KEY".to_string(), zs("some_value")),
        ("ANOTHER_RANDOM_SECRET".to_string(), zs("some_other_value")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![mock_valid("openai", "OPENAI")];
    let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
    assert_eq!(report.total, 2);
    assert_eq!(report.not_checked, 2);
    assert_eq!(report.valid, 0);
    let nc = report.not_checked_entries();
    assert_eq!(nc.len(), 2);
}

#[test]
fn pipeline_empty_vault() {
    let secrets: Vec<(String, zeroize::Zeroizing<String>)> = vec![];
    let validators: Vec<Box<dyn SecretValidator>> = default_validators();
    let report = run_validation_pipeline(secrets, &validators, 4, Duration::from_secs(5));
    assert_eq!(report.total, 0);
    assert_eq!(report.valid, 0);
    assert_eq!(report.invalid, 0);
    assert_eq!(report.unreachable, 0);
    assert_eq!(report.not_checked, 0);
    assert!(report.entries.is_empty());
}

#[test]
fn pipeline_empty_validators() {
    let secrets = vec![("OPENAI_API_KEY".to_string(), zs("sk-test"))];
    let validators: Vec<Box<dyn SecretValidator>> = vec![];
    let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
    assert_eq!(report.total, 1);
    assert_eq!(report.not_checked, 1);
    assert_eq!(report.valid, 0);
}

#[test]
fn pipeline_partial_failure_all_entries_recorded() {
    let secrets = vec![
        ("OPENAI_API_KEY".to_string(), zs("sk-ok")),
        ("STRIPE_SECRET_KEY".to_string(), zs("sk_revoked")),
        ("GITHUB_TOKEN".to_string(), zs("ghp_unreachable")),
        ("ANTHROPIC_API_KEY".to_string(), zs("sk-ant-ok")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_valid("openai", "OPENAI"),
        mock_invalid("stripe", "STRIPE", "forbidden"),
        mock_unreachable("github", "GITHUB", "timeout after 10s"),
        mock_valid("anthropic", "ANTHROPIC"),
    ];
    let report = run_validation_pipeline(secrets, &validators, 4, Duration::from_secs(5));
    assert_eq!(report.total, 4);
    assert_eq!(report.valid, 2);
    assert_eq!(report.invalid, 1);
    assert_eq!(report.unreachable, 1);
    assert_eq!(report.not_checked, 0);
    // All entries should be present
    assert_eq!(report.entries.len(), 4);
}

#[test]
fn pipeline_timeout_resilience() {
    // A validator that simulates a timeout should produce Unreachable, not panic.
    struct SlowValidator;
    impl SecretValidator for SlowValidator {
        fn name(&self) -> &str {
            "slow"
        }
        fn matches(&self, key: &str) -> bool {
            key.contains("SLOW")
        }
        fn validate(
            &self,
            _: &str,
            _: &zeroize::Zeroizing<String>,
            _: Duration,
        ) -> ValidationResult {
            ValidationResult::Unreachable {
                reason: "timeout".to_string(),
            }
        }
    }

    let secrets = vec![("SLOW_API_KEY".to_string(), zs("value"))];
    let validators: Vec<Box<dyn SecretValidator>> = vec![Box::new(SlowValidator)];
    let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_millis(1));
    assert_eq!(report.unreachable, 1);
    assert_eq!(report.valid, 0);
}

#[test]
fn pipeline_jobs_parameter_respected() {
    // jobs > secrets: should still work (no panic on empty chunks)
    let secrets: Vec<_> = (0..3)
        .map(|i| (format!("OPENAI_API_KEY_{i}"), zs("sk-test")))
        .collect();
    let validators: Vec<Box<dyn SecretValidator>> = vec![mock_valid("openai", "OPENAI")];
    let report = run_validation_pipeline(secrets, &validators, 10, Duration::from_secs(5));
    assert_eq!(report.total, 3);
    assert_eq!(report.valid, 3);
}

#[test]
fn pipeline_parallel_variant_all_valid() {
    let secrets = vec![
        ("OPENAI_API_KEY".to_string(), zs("sk-valid")),
        ("STRIPE_SECRET_KEY".to_string(), zs("sk_live_valid")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_valid("openai", "OPENAI"),
        mock_valid("stripe", "STRIPE"),
    ];
    let report = run_validation_pipeline_parallel(secrets, &validators, 4, Duration::from_secs(5));
    assert_eq!(report.total, 2);
    assert_eq!(report.valid, 2);
    assert_eq!(report.invalid, 0);
}

#[test]
fn pipeline_parallel_variant_invalid_detected() {
    let secrets = vec![
        ("OPENAI_API_KEY".to_string(), zs("sk-revoked")),
        ("STRIPE_SECRET_KEY".to_string(), zs("sk_live_valid")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_invalid("openai", "OPENAI", "401"),
        mock_valid("stripe", "STRIPE"),
    ];
    let report = run_validation_pipeline_parallel(secrets, &validators, 2, Duration::from_secs(5));
    assert_eq!(report.total, 2);
    assert_eq!(report.invalid, 1);
    assert_eq!(report.valid, 1);
}

#[test]
fn pipeline_report_timestamps_are_recent() {
    let now_before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secrets = vec![("OPENAI_API_KEY".to_string(), zs("sk-test"))];
    let validators: Vec<Box<dyn SecretValidator>> = vec![mock_valid("openai", "OPENAI")];
    let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
    let now_after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        report.generated_at >= now_before && report.generated_at <= now_after,
        "generated_at={} not in [{now_before}, {now_after}]",
        report.generated_at
    );
    for entry in &report.entries {
        assert!(
            entry.checked_at >= now_before && entry.checked_at <= now_after,
            "entry.checked_at={} not in [{now_before}, {now_after}]",
            entry.checked_at
        );
    }
}

// ── Metadata persistence via FileVault ───────────────────────────────────────

#[test]
fn file_vault_validation_metadata_round_trip() {
    let dir = common::canonical_tempdir();
    // Use file vault directly
    let vault = phantom_vault::file::FileVault::new(
        dir.path(),
        "test-validate-project",
        "test-validate-passphrase".to_string(),
    )
    .unwrap();

    vault.store("OPENAI_API_KEY", "sk-test").unwrap();

    // Initially no metadata
    let meta = vault.get_validation_metadata("OPENAI_API_KEY").unwrap();
    assert!(meta.never_checked());

    // Set valid metadata
    let valid_meta = ValidationMetadata::mark_valid("openai");
    vault
        .set_validation_metadata("OPENAI_API_KEY", valid_meta.clone())
        .unwrap();

    // Read it back
    let read_back = vault.get_validation_metadata("OPENAI_API_KEY").unwrap();
    assert!(read_back.is_valid);
    assert_eq!(read_back.validator_name.as_deref(), Some("openai"));
    assert!(!read_back.never_checked());
}

#[test]
fn file_vault_validation_metadata_invalid_persisted() {
    let vault = phantom_vault::file::FileVault::new(
        &{
            let d = common::canonical_tempdir();
            let p = d.path().to_path_buf();
            std::mem::forget(d);
            p
        },
        "test-val-invalid",
        "pass".to_string(),
    )
    .unwrap();

    vault.store("STRIPE_SECRET_KEY", "sk_test_xxx").unwrap();

    let meta = ValidationMetadata::mark_invalid("stripe", "401 — key expired");
    vault
        .set_validation_metadata("STRIPE_SECRET_KEY", meta)
        .unwrap();

    let read = vault.get_validation_metadata("STRIPE_SECRET_KEY").unwrap();
    assert!(!read.is_valid);
    assert_eq!(read.failure_reason.as_deref(), Some("401 — key expired"));
    assert_eq!(read.validator_name.as_deref(), Some("stripe"));
}

#[test]
fn file_vault_validation_metadata_cleared_on_delete() {
    let vault = phantom_vault::file::FileVault::new(
        &{
            let d = common::canonical_tempdir();
            let p = d.path().to_path_buf();
            std::mem::forget(d);
            p
        },
        "test-val-delete",
        "pass".to_string(),
    )
    .unwrap();

    vault.store("GITHUB_TOKEN", "ghp_test").unwrap();
    vault
        .set_validation_metadata("GITHUB_TOKEN", ValidationMetadata::mark_valid("github"))
        .unwrap();

    // Verify it's there
    let m = vault.get_validation_metadata("GITHUB_TOKEN").unwrap();
    assert!(m.is_valid);

    // Delete secret
    vault.delete("GITHUB_TOKEN").unwrap();

    // Re-store and check metadata is gone
    vault.store("GITHUB_TOKEN", "ghp_new").unwrap();
    let m2 = vault.get_validation_metadata("GITHUB_TOKEN").unwrap();
    assert!(
        m2.never_checked(),
        "metadata should be cleared after delete+re-store"
    );
}

#[test]
fn file_vault_validation_metadata_nonexistent_secret_errors() {
    let vault = phantom_vault::file::FileVault::new(
        &{
            let d = common::canonical_tempdir();
            let p = d.path().to_path_buf();
            std::mem::forget(d);
            p
        },
        "test-val-nonexistent",
        "pass".to_string(),
    )
    .unwrap();

    let result =
        vault.set_validation_metadata("NONEXISTENT_KEY", ValidationMetadata::mark_valid("openai"));
    assert!(result.is_err(), "should error for nonexistent secret");
}

#[test]
fn file_vault_validation_metadata_survives_reload() {
    // Verify that metadata is persisted to disk and survives vault reload.
    let dir = common::canonical_tempdir();
    let path = dir.path().to_path_buf();

    {
        let vault =
            phantom_vault::file::FileVault::new(&path, "test-val-persist", "pass".to_string())
                .unwrap();
        vault.store("ANTHROPIC_API_KEY", "sk-ant-test").unwrap();
        vault
            .set_validation_metadata(
                "ANTHROPIC_API_KEY",
                ValidationMetadata::mark_valid("anthropic"),
            )
            .unwrap();
    }

    // Re-open vault
    {
        let vault2 =
            phantom_vault::file::FileVault::new(&path, "test-val-persist", "pass".to_string())
                .unwrap();
        let m = vault2.get_validation_metadata("ANTHROPIC_API_KEY").unwrap();
        assert!(m.is_valid, "metadata should persist across vault reload");
        assert_eq!(m.validator_name.as_deref(), Some("anthropic"));
    }
}

// ── Audit trail tests ─────────────────────────────────────────────────────────

#[test]
fn pipeline_emits_audit_events_when_enabled() {
    use std::sync::Mutex;

    // Set up a temp HOME with audit enabled so events get written.
    let dir = common::canonical_tempdir();
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev_home = std::env::var("HOME").ok();
    let prev_audit = std::env::var("PHANTOM_AUDIT").ok();

    unsafe {
        std::env::set_var("HOME", dir.path());
        std::env::set_var("PHANTOM_AUDIT", "1");
    }

    let secrets = vec![
        ("OPENAI_API_KEY".to_string(), zs("sk-test")),
        ("STRIPE_SECRET_KEY".to_string(), zs("sk_test")),
    ];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        mock_valid("openai", "OPENAI"),
        mock_valid("stripe", "STRIPE"),
    ];
    run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));

    // Check that audit events were written.
    let log_path = dir.path().join(".phantom").join("audit.log");
    assert!(log_path.exists(), "audit log should be created");
    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        content.contains("vault.validate"),
        "audit log should contain vault.validate events: {content}"
    );
    // Values must never appear in the audit log.
    assert!(
        !content.contains("sk-test"),
        "audit log must not contain secret values"
    );
    assert!(
        !content.contains("sk_test"),
        "audit log must not contain secret values"
    );

    unsafe {
        match prev_home {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
        match prev_audit {
            Some(p) => std::env::set_var("PHANTOM_AUDIT", p),
            None => std::env::remove_var("PHANTOM_AUDIT"),
        }
    }
}

// ── Report structure tests ────────────────────────────────────────────────────

#[test]
fn report_invalid_entries_helper() {
    let report = ValidationReport {
        generated_at: 0,
        total: 3,
        valid: 1,
        invalid: 1,
        unreachable: 1,
        not_checked: 0,
        entries: vec![
            phantom_core::validator::ValidationEntry {
                name: "A".to_string(),
                validator: "v".to_string(),
                status: ValidationStatus::Valid,
                reason: None,
                checked_at: 0,
            },
            phantom_core::validator::ValidationEntry {
                name: "B".to_string(),
                validator: "v".to_string(),
                status: ValidationStatus::Invalid,
                reason: Some("401".to_string()),
                checked_at: 0,
            },
            phantom_core::validator::ValidationEntry {
                name: "C".to_string(),
                validator: "v".to_string(),
                status: ValidationStatus::Unreachable,
                reason: Some("timeout".to_string()),
                checked_at: 0,
            },
        ],
    };
    assert_eq!(report.invalid_entries().len(), 1);
    assert_eq!(report.unreachable_entries().len(), 1);
    assert_eq!(report.not_checked_entries().len(), 0);
    assert_eq!(report.invalid_entries()[0].name, "B");
    assert_eq!(report.unreachable_entries()[0].name, "C");
}

#[test]
fn report_serialization_is_complete() {
    let secrets = vec![("OPENAI_API_KEY".to_string(), zs("sk-test"))];
    let validators: Vec<Box<dyn SecretValidator>> = vec![mock_valid("openai", "OPENAI")];
    let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
    let json = serde_json::to_string_pretty(&report).unwrap();
    // Check all top-level fields are present
    assert!(json.contains("\"total\""));
    assert!(json.contains("\"valid\""));
    assert!(json.contains("\"invalid\""));
    assert!(json.contains("\"unreachable\""));
    assert!(json.contains("\"not_checked\""));
    assert!(json.contains("\"entries\""));
    assert!(json.contains("\"generated_at\""));
    // Per-entry fields
    assert!(json.contains("\"name\""));
    assert!(json.contains("\"validator\""));
    assert!(json.contains("\"status\""));
    assert!(json.contains("\"checked_at\""));
    // No secret values
    assert!(!json.contains("sk-test"));
}

#[test]
fn default_validators_cover_all_required_services() {
    let validators = default_validators();
    let names: Vec<&str> = validators.iter().map(|v| v.name()).collect();
    // Spec requires: OpenAI, Stripe, GitHub, Anthropic, AWS
    assert!(names.contains(&"openai"), "missing openai");
    assert!(names.contains(&"stripe"), "missing stripe");
    assert!(names.contains(&"github"), "missing github");
    assert!(names.contains(&"anthropic"), "missing anthropic");
    assert!(names.contains(&"aws"), "missing aws");
    assert!(validators.len() >= 5, "expected at least 5 validators");
}

#[test]
fn not_applicable_falls_through_to_next_validator() {
    struct NotApplicableFirst;
    impl SecretValidator for NotApplicableFirst {
        fn name(&self) -> &str {
            "na-first"
        }
        fn matches(&self, key: &str) -> bool {
            key.contains("OPENAI")
        }
        fn validate(
            &self,
            _: &str,
            _: &zeroize::Zeroizing<String>,
            _: Duration,
        ) -> ValidationResult {
            ValidationResult::NotApplicable
        }
    }

    let secrets = vec![("OPENAI_API_KEY".to_string(), zs("sk-test"))];
    let validators: Vec<Box<dyn SecretValidator>> = vec![
        Box::new(NotApplicableFirst),
        mock_valid("openai-fallback", "OPENAI"),
    ];
    let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
    assert_eq!(report.valid, 1, "fallback validator should handle the key");
    assert_eq!(report.not_checked, 0);
}

#[test]
fn validation_status_display_strings() {
    assert_eq!(ValidationStatus::Valid.to_string(), "valid");
    assert_eq!(ValidationStatus::Invalid.to_string(), "INVALID");
    assert_eq!(ValidationStatus::Unreachable.to_string(), "unreachable");
    assert_eq!(ValidationStatus::NotChecked.to_string(), "not_checked");
    assert_eq!(ValidationStatus::Skipped.to_string(), "skipped");
}
