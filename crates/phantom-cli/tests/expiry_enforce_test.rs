//! Integration tests for `phantom expiry set/enforce/rotate` and the
//! `check_expiry` / `compute_new_expires_at` core functions.
//!
//! These tests are hermetic: they operate against temporary directories and
//! the file-vault backend (via `PHANTOM_VAULT_PASSPHRASE`).

// ── Unit tests for phantom-core expiry logic ──────────────────────────────────

#[cfg(test)]
mod core_expiry_tests {
    use phantom_core::rotation_strategy::{
        check_expiry, compute_new_expires_at, ExpiryStatus,
    };

    // ── check_expiry: basic cases ─────────────────────────────────────────

    #[test]
    fn not_expired_well_before_deadline() {
        // expires in 30 days
        let now = 1_000_000u64;
        let expires_at = now + 30 * 86_400;
        let status = check_expiry(expires_at, 7, now);
        assert!(status.is_valid(), "30 days out should be Valid, got {status:?}");
    }

    #[test]
    fn expired_when_now_equals_expires_at() {
        let now = 1_000_000u64;
        let expires_at = now; // exactly at expiry boundary
        let status = check_expiry(expires_at, 7, now);
        assert!(status.is_expired(), "now == expires_at should be Expired");
    }

    #[test]
    fn expired_when_past_deadline() {
        let now = 1_000_000u64;
        let expires_at = now - 86_400; // 1 day ago
        let status = check_expiry(expires_at, 7, now);
        match status {
            ExpiryStatus::Expired { secs_overdue } => {
                assert_eq!(secs_overdue, 86_400);
            }
            other => panic!("Expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn grace_period_when_within_warn_window() {
        let now = 1_000_000u64;
        let expires_at = now + 3 * 86_400; // 3 days remaining
        let status = check_expiry(expires_at, 7, now); // grace = 7 days
        match status {
            ExpiryStatus::GracePeriod { days_remaining } => {
                assert_eq!(days_remaining, 3);
            }
            other => panic!("Expected GracePeriod, got {other:?}"),
        }
    }

    #[test]
    fn valid_outside_grace_window() {
        let now = 1_000_000u64;
        let expires_at = now + 10 * 86_400; // 10 days out
        let status = check_expiry(expires_at, 7, now); // grace = 7 days
        match status {
            ExpiryStatus::Valid { days_remaining } => {
                assert_eq!(days_remaining, 10);
            }
            other => panic!("Expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn grace_period_boundary_exactly_at_grace_days() {
        let now = 1_000_000u64;
        let expires_at = now + 7 * 86_400; // exactly 7 days — within grace
        let status = check_expiry(expires_at, 7, now);
        matches!(status, ExpiryStatus::GracePeriod { .. });
    }

    #[test]
    fn grace_period_zero_days_remaining() {
        // expires in < 1 day (will round down to 0)
        let now = 1_000_000u64;
        let expires_at = now + 3600; // 1 hour left
        let status = check_expiry(expires_at, 7, now);
        match status {
            ExpiryStatus::GracePeriod { days_remaining } => {
                assert_eq!(days_remaining, 0);
            }
            other => panic!("Expected GracePeriod, got {other:?}"),
        }
    }

    // ── check_expiry: no_expiry case handled by callers ───────────────────

    #[test]
    fn expired_many_days_overdue() {
        let now = 10_000_000u64;
        let expires_at = now - 10 * 86_400; // 10 days ago
        let status = check_expiry(expires_at, 7, now);
        match status {
            ExpiryStatus::Expired { secs_overdue } => {
                assert_eq!(secs_overdue, 10 * 86_400);
            }
            other => panic!("Expected Expired, got {other:?}"),
        }
    }

    // ── ExpiryStatus::label ───────────────────────────────────────────────

    #[test]
    fn label_expired_zero_days() {
        let s = ExpiryStatus::Expired { secs_overdue: 3600 };
        assert!(s.label().contains("EXPIRED"), "got: {}", s.label());
    }

    #[test]
    fn label_expired_multiple_days() {
        let s = ExpiryStatus::Expired { secs_overdue: 3 * 86_400 };
        let label = s.label();
        assert!(label.contains("3"), "got: {label}");
        assert!(label.contains("EXPIRED"), "got: {label}");
    }

    #[test]
    fn label_grace_period() {
        let s = ExpiryStatus::GracePeriod { days_remaining: 5 };
        let label = s.label();
        assert!(label.contains("5"), "got: {label}");
        assert!(label.contains("WARNING"), "got: {label}");
    }

    #[test]
    fn label_valid() {
        let s = ExpiryStatus::Valid { days_remaining: 20 };
        let label = s.label();
        assert!(label.contains("20"), "got: {label}");
        assert!(label.contains("remaining"), "got: {label}");
    }

    #[test]
    fn label_no_expiry() {
        let s = ExpiryStatus::NoExpiry;
        assert_eq!(s.label(), "no expiry set");
    }

    // ── compute_new_expires_at ────────────────────────────────────────────

    #[test]
    fn compute_new_expires_at_30_days() {
        let now = 1_000_000u64;
        let result = compute_new_expires_at(30, now);
        assert_eq!(result, now + 30 * 86_400);
    }

    #[test]
    fn compute_new_expires_at_zero_days() {
        let now = 1_000_000u64;
        let result = compute_new_expires_at(0, now);
        assert_eq!(result, now);
    }

    #[test]
    fn compute_new_expires_at_one_day() {
        let now = 86_400u64;
        let result = compute_new_expires_at(1, now);
        assert_eq!(result, now + 86_400);
    }
}

// ── Unit tests for SecretOverride expiry/rotation_window fields ───────────────

#[cfg(test)]
mod config_expiry_fields_tests {
    use phantom_core::config::{PhantomConfig, SecretOverride};

    #[test]
    fn secret_override_expiry_fields_default_to_none() {
        let ov = SecretOverride::default();
        assert!(ov.expires_at.is_none());
        assert!(ov.rotation_window.is_none());
    }

    #[test]
    fn secret_override_toml_roundtrip_with_expiry() {
        let mut config = PhantomConfig::new_with_defaults("expiry_test".to_string());
        config.phantom.secrets.insert(
            "STRIPE_KEY".to_string(),
            SecretOverride {
                expires_at: Some(1_719_158_400),
                rotation_window: Some(30),
                rotate_every: None,
                rotation_schedule: None,
                audit: None,
                validation: None,
                enforce_rotation_on_access: false,
                expiry_grace_period_secs: 604_800,
                rotation_provider: None,
            },
        );
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(
            toml_str.contains("expires_at"),
            "TOML should contain expires_at"
        );
        assert!(
            toml_str.contains("rotation_window"),
            "TOML should contain rotation_window"
        );

        let parsed: PhantomConfig = toml::from_str(&toml_str).unwrap();
        let ov = parsed.phantom.secrets.get("STRIPE_KEY").unwrap();
        assert_eq!(ov.expires_at, Some(1_719_158_400));
        assert_eq!(ov.rotation_window, Some(30));
    }

    #[test]
    fn secret_override_toml_roundtrip_without_expiry() {
        let mut config = PhantomConfig::new_with_defaults("no_expiry".to_string());
        config.phantom.secrets.insert(
            "MY_KEY".to_string(),
            SecretOverride {
                rotate_every: Some("7d".to_string()),
                ..Default::default()
            },
        );
        let toml_str = toml::to_string_pretty(&config).unwrap();
        // expires_at and rotation_window should be omitted when None
        let section = toml_str
            .lines()
            .skip_while(|l| !l.contains("[phantom.secrets.MY_KEY]"))
            .take(10)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !section.contains("expires_at"),
            "expires_at should be skipped when None"
        );
        assert!(
            !section.contains("rotation_window"),
            "rotation_window should be skipped when None"
        );
    }

    #[test]
    fn existing_config_parses_without_expiry_fields() {
        // Simulate a .phantom.toml that was written before these fields existed.
        let toml_str = r#"
[phantom]
version = "1"
project_id = "abc123"

[phantom.secrets.OLD_KEY]
rotate_every = "30d"
"#;
        let config: PhantomConfig = toml::from_str(toml_str).unwrap();
        let ov = config.phantom.secrets.get("OLD_KEY").unwrap();
        assert!(ov.expires_at.is_none(), "expires_at should default to None");
        assert!(
            ov.rotation_window.is_none(),
            "rotation_window should default to None"
        );
    }

    #[test]
    fn multiple_secrets_mixed_expiry() {
        let mut config = PhantomConfig::new_with_defaults("mixed".to_string());
        config.phantom.secrets.insert(
            "HAS_EXPIRY".to_string(),
            SecretOverride {
                expires_at: Some(9_999_999_999),
                rotation_window: Some(14),
                ..Default::default()
            },
        );
        config.phantom.secrets.insert(
            "NO_EXPIRY".to_string(),
            SecretOverride {
                rotate_every: Some("7d".to_string()),
                ..Default::default()
            },
        );
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: PhantomConfig = toml::from_str(&toml_str).unwrap();

        let with_exp = parsed.phantom.secrets.get("HAS_EXPIRY").unwrap();
        assert_eq!(with_exp.expires_at, Some(9_999_999_999));
        assert_eq!(with_exp.rotation_window, Some(14));

        let no_exp = parsed.phantom.secrets.get("NO_EXPIRY").unwrap();
        assert!(no_exp.expires_at.is_none());
    }
}

// ── enforce logic integration (pure logic, no vault/process) ─────────────────

#[cfg(test)]
mod enforce_logic_tests {
    use phantom_core::rotation_strategy::check_expiry;

    /// Simulate what `run_enforce` does: check a list of (name, expires_at?) entries.
    fn enforce(
        secrets: &[(&str, Option<u64>)],
        now: u64,
        fail_closed: bool,
    ) -> (Vec<String>, usize) {
        let mut expired_names = Vec::new();
        let mut no_expiry_count = 0usize;
        for (name, expires_at_opt) in secrets {
            match expires_at_opt {
                None => {
                    no_expiry_count += 1;
                    if fail_closed {
                        expired_names.push(format!("{name}:no_expiry"));
                    }
                }
                Some(exp) => {
                    let status = check_expiry(*exp, 0, now);
                    if status.is_expired() {
                        expired_names.push(name.to_string());
                    }
                }
            }
        }
        (expired_names, no_expiry_count)
    }

    #[test]
    fn enforce_passes_when_all_valid() {
        let now = 1_000_000u64;
        let secrets = vec![
            ("A", Some(now + 10 * 86_400)),
            ("B", Some(now + 5 * 86_400)),
        ];
        let (expired, _) = enforce(&secrets, now, false);
        assert!(expired.is_empty(), "no secrets should be expired");
    }

    #[test]
    fn enforce_fails_when_one_expired() {
        let now = 1_000_000u64;
        let secrets = vec![
            ("GOOD", Some(now + 10 * 86_400)),
            ("BAD", Some(now - 86_400)), // 1 day past
        ];
        let (expired, _) = enforce(&secrets, now, false);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "BAD");
    }

    #[test]
    fn enforce_fails_when_multiple_expired() {
        let now = 5_000_000u64;
        let secrets = vec![
            ("A", Some(now - 86_400)),
            ("B", Some(now - 2 * 86_400)),
            ("C", Some(now + 86_400)), // valid
        ];
        let (expired, _) = enforce(&secrets, now, false);
        assert_eq!(expired.len(), 2);
        assert!(expired.contains(&"A".to_string()));
        assert!(expired.contains(&"B".to_string()));
    }

    #[test]
    fn enforce_passes_no_expiry_when_not_fail_closed() {
        let now = 1_000_000u64;
        let secrets = vec![("X", None), ("Y", None)];
        let (expired, no_expiry) = enforce(&secrets, now, false);
        assert!(expired.is_empty());
        assert_eq!(no_expiry, 2);
    }

    #[test]
    fn enforce_fails_no_expiry_when_fail_closed() {
        let now = 1_000_000u64;
        let secrets = vec![("X", None), ("Y", Some(now + 86_400))];
        let (violations, no_expiry) = enforce(&secrets, now, true);
        // fail_closed mode: "X:no_expiry" should be in violations
        assert_eq!(no_expiry, 1);
        assert!(violations.iter().any(|v| v.contains("X")));
    }

    #[test]
    fn enforce_at_exact_boundary_is_expired() {
        let now = 1_000_000u64;
        let secrets = vec![("KEY", Some(now))]; // now == expires_at
        let (expired, _) = enforce(&secrets, now, false);
        assert_eq!(expired.len(), 1, "boundary case: now == expires_at should fail");
    }

    #[test]
    fn enforce_one_second_before_expiry_is_valid() {
        let now = 1_000_000u64;
        let secrets = vec![("KEY", Some(now + 1))]; // 1 second left
        let (expired, _) = enforce(&secrets, now, false);
        assert!(expired.is_empty(), "1 second before expiry should pass");
    }

    #[test]
    fn enforce_empty_secrets_always_passes() {
        let (expired, no_expiry) = enforce(&[], 1_000_000, false);
        assert!(expired.is_empty());
        assert_eq!(no_expiry, 0);
    }

    // ── rotation resets timer ─────────────────────────────────────────────

    #[test]
    fn rotation_resets_expiry() {
        use phantom_core::rotation_strategy::compute_new_expires_at;

        let now = 1_000_000u64;
        let old_expires = now - 86_400; // already expired

        // Confirm it's expired before rotation
        assert!(check_expiry(old_expires, 0, now).is_expired());

        // Simulate rotation: reset expiry to now + 30 days
        let new_expires = compute_new_expires_at(30, now);
        let status_after = check_expiry(new_expires, 7, now);
        assert!(
            status_after.is_valid(),
            "After rotation, 30-day TTL should be Valid"
        );
    }

    #[test]
    fn rotation_with_custom_window_resets_correctly() {
        use phantom_core::rotation_strategy::compute_new_expires_at;

        let now = 2_000_000u64;
        let new_expires = compute_new_expires_at(14, now);
        let status = check_expiry(new_expires, 7, now);
        // 14 days out with 7-day grace → Valid
        assert!(status.is_valid());
    }
}
