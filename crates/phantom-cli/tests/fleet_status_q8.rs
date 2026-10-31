//! Integration tests for `phantom fleet-status` (job RQ-PSFLEETSTATQ8).
//!
//! The command is a read-only, value-free fleet view: secret names, expiry
//! state, the last stored validation result, and overdue rotations. All
//! fixture values below are fake, planted only so the test can prove they
//! never appear on stdout or stderr.

mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::process::Output;
use tempfile::TempDir;

const VAULT_PASS: &str = "test-integration-passphrase-fleet-status-q8";
const DAY: u64 = 86_400;

// Fake fixture values; each is asserted absent from every output stream.
const FRESH_VALUE: &str = "fake-fleet-q8-fresh-value-1";
const EXPIRED_VALUE: &str = "fake-fleet-q8-expired-value-2";
const STALE_VALUE: &str = "fake-fleet-q8-stale-value-3";
const NEVER_VALUE: &str = "fake-fleet-q8-never-value-4";

fn phantom(dir: &TempDir) -> Command {
    common::phantom(dir, VAULT_PASS)
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process exited by signal")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Every planted fixture value and every `phm_` mapping must stay out of both
/// streams, on success and on failure.
fn assert_value_free(output: &Output) {
    for needle in [
        FRESH_VALUE,
        EXPIRED_VALUE,
        STALE_VALUE,
        NEVER_VALUE,
        VAULT_PASS,
        "phm_",
    ] {
        assert!(
            !stdout(output).contains(needle),
            "stdout leaked {needle}: {}",
            stdout(output)
        );
        assert!(
            !stderr(output).contains(needle),
            "stderr leaked {needle}: {}",
            stderr(output)
        );
    }
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn open_vault(dir: &TempDir) -> phantom_vault::file::FileVault {
    let config =
        phantom_core::config::PhantomConfig::load(&dir.path().join(".phantom.toml")).unwrap();
    // <base>/vaults/<project>.vault — FileVault::new wants the base.
    let encrypted = common::encrypted_file(dir, config.local_project_id());
    let vaults = encrypted.parent().unwrap();
    assert!(
        vaults.is_dir(),
        "init created the encrypted-file vault directory"
    );
    assert!(
        encrypted.with_extension("lock").is_file(),
        "init provisioned this project's encrypted-file vault"
    );
    let base = vaults.parent().unwrap();
    phantom_vault::file::FileVault::new(base, config.local_project_id(), VAULT_PASS.to_string())
        .unwrap()
}

/// Seed a project where every posture state is represented, using fake values
/// and hand-stamped metadata:
/// - `FRESH_API_KEY`: valid, expiring in 30 days, last check valid.
/// - `EXPIRED_TOKEN`: expired 2 days ago, demoted read-only, last check invalid.
/// - `STALE_ROTATION`: 45 days old under a 30-day enforced schedule → overdue.
/// - `NEVER_CHECKED`: no expiry, never validated.
fn fleet_project() -> TempDir {
    use phantom_vault::VaultBackend;
    let dir = common::canonical_tempdir();
    phantom(&dir).args(["init", "--empty"]).assert().success();

    // Rotation schedule for STALE_ROTATION (enforced 30d) and a service
    // mapping for FRESH_API_KEY, written through the config type.
    let config_path = dir.path().join(".phantom.toml");
    let mut config = phantom_core::config::PhantomConfig::load(&config_path).unwrap();
    config.phantom.secrets.insert(
        "STALE_ROTATION".to_string(),
        phantom_core::config::SecretOverride {
            rotate_every: Some("30d".to_string()),
            enforce_rotation_on_access: true,
            ..Default::default()
        },
    );
    config.services.insert(
        "fixture".to_string(),
        phantom_core::config::ServiceConfig {
            secret_key: "FRESH_API_KEY".to_string(),
            pattern: Some("fixture.invalid".to_string()),
            header: Some("Authorization".to_string()),
            header_format: Some("Bearer {secret}".to_string()),
            secret_type: "api_key".to_string(),
        },
    );
    config.save(&config_path).unwrap();

    let now = phantom_vault::metadata::now_secs();
    let vault = open_vault(&dir);
    let put = |name: &str, value: &str, meta: phantom_vault::SecretMetadata| {
        vault.store(name, value).unwrap();
        vault.set_metadata(name, meta).unwrap();
    };
    let checked = |name: &str, meta: phantom_core::validator::ValidationMetadata| {
        vault.set_validation_metadata(name, meta).unwrap();
    };

    put(
        "FRESH_API_KEY",
        FRESH_VALUE,
        phantom_vault::SecretMetadata {
            created_at: Some(now - DAY),
            expires_at: Some(now + 30 * DAY),
            ..Default::default()
        },
    );
    checked(
        "FRESH_API_KEY",
        phantom_core::validator::ValidationMetadata {
            last_check_ts: now - 3_600,
            is_valid: true,
            failure_reason: None,
            validator_name: Some("fixture-validator".to_string()),
        },
    );

    put(
        "EXPIRED_TOKEN",
        EXPIRED_VALUE,
        phantom_vault::SecretMetadata {
            created_at: Some(now - 60 * DAY),
            expires_at: Some(now - 2 * DAY),
            vault_mode: phantom_vault::metadata::VaultMode::ReadOnly,
            ..Default::default()
        },
    );
    checked(
        "EXPIRED_TOKEN",
        phantom_core::validator::ValidationMetadata {
            last_check_ts: now - 7_200,
            is_valid: false,
            failure_reason: Some("fixture: provider rejected the credential".to_string()),
            validator_name: Some("fixture-validator".to_string()),
        },
    );

    put(
        "STALE_ROTATION",
        STALE_VALUE,
        phantom_vault::SecretMetadata {
            created_at: Some(now - 45 * DAY),
            ..Default::default()
        },
    );

    put(
        "NEVER_CHECKED",
        NEVER_VALUE,
        phantom_vault::SecretMetadata {
            created_at: Some(now - DAY),
            ..Default::default()
        },
    );

    dir
}

fn secret<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("secret {name} missing from report: {report}"))
}

#[test]
fn fleet_status_json_reports_names_expiry_validation_and_overdue_rotations() {
    let dir = fleet_project();
    let output = phantom(&dir)
        .args(["fleet-status", "--json"])
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_value_free(&output);

    let report = json_stdout(&output);
    assert_eq!(report["schema"], "phantom.fleet_status.v1");
    assert_eq!(report["kind"], "phantom.fleet_status.v1");
    assert_eq!(report["inventory"], "complete");
    assert_eq!(report["expiring_within_days"], 7);
    assert_eq!(report["needs_attention"], true);
    assert!(report["generated_at"].as_u64().unwrap() > 0);
    assert_eq!(report["vault_backend"], "encrypted-file");

    // Rows are sorted by vault entry name.
    let names: Vec<&str> = report["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "EXPIRED_TOKEN",
            "FRESH_API_KEY",
            "NEVER_CHECKED",
            "STALE_ROTATION"
        ]
    );

    let fresh = secret(&report, "FRESH_API_KEY");
    assert_eq!(fresh["environment"], "default");
    assert_eq!(fresh["detected_service"], "fixture");
    assert_eq!(fresh["attention"], false);
    assert_eq!(fresh["expiry"]["state"], "valid");
    assert_eq!(fresh["expiry"]["read_only"], false);
    assert!(fresh["expiry"]["days_remaining"].as_i64().unwrap() > 25);
    assert_eq!(fresh["validation"]["state"], "valid");
    assert_eq!(fresh["validation"]["stale"], false);
    assert_eq!(fresh["validation"]["validator"], "fixture-validator");
    assert_eq!(fresh["rotation"]["state"], "no_schedule");
    assert_eq!(fresh["rotation"]["enforced"], false);

    let expired = secret(&report, "EXPIRED_TOKEN");
    assert_eq!(expired["expiry"]["state"], "expired");
    assert_eq!(expired["expiry"]["read_only"], true);
    assert!(expired["expiry"]["days_remaining"].as_i64().unwrap() < 0);
    assert_eq!(expired["validation"]["state"], "invalid");
    assert_eq!(
        expired["validation"]["failure_reason"],
        "fixture: provider rejected the credential"
    );
    assert_eq!(expired["attention"], true);

    let stale = secret(&report, "STALE_ROTATION");
    assert_eq!(stale["rotation"]["state"], "overdue");
    assert_eq!(stale["rotation"]["enforced"], true);
    assert_eq!(stale["rotation"]["schedule"], "every 30 days");
    assert!(stale["rotation"]["anchor"].as_u64().unwrap() > 0);
    assert!(stale["rotation"]["due_at"].as_u64().unwrap() > 0);
    assert_eq!(stale["validation"]["state"], "never_checked");
    assert_eq!(stale["attention"], true);

    let never = secret(&report, "NEVER_CHECKED");
    assert_eq!(never["environment"], "default");
    assert_eq!(never["detected_service"], Value::Null);
    assert_eq!(never["expiry"]["state"], "none");
    assert_eq!(never["validation"]["state"], "never_checked");
    assert_eq!(never["validation"]["checked_at"], Value::Null);
    assert_eq!(never["attention"], false);

    assert_eq!(
        report["overdue_rotations"],
        serde_json::json!(["EXPIRED_TOKEN", "STALE_ROTATION"])
    );

    let summary = &report["summary"];
    assert_eq!(summary["secrets"], 4);
    assert_eq!(summary["expired"], 1);
    assert_eq!(summary["read_only"], 1);
    assert_eq!(summary["validation_invalid"], 1);
    assert_eq!(summary["validation_never_checked"], 2);
    assert_eq!(summary["rotation_overdue"], 1);
    assert_eq!(summary["overdue_rotations"], 2);
    assert_eq!(summary["needs_attention"], 2);
}

#[test]
fn fleet_status_json_expiring_within_window_and_env_scoped_names() {
    use phantom_vault::VaultBackend;
    let dir = fleet_project();
    let now = phantom_vault::metadata::now_secs();
    let vault = open_vault(&dir);
    vault
        .store("staging/SCOPED_KEY", "fake-fleet-q8-scoped-5")
        .unwrap();
    vault
        .set_metadata(
            "staging/SCOPED_KEY",
            phantom_vault::SecretMetadata {
                created_at: Some(now - DAY),
                expires_at: Some(now + 45 * DAY),
                ..Default::default()
            },
        )
        .unwrap();

    let output = phantom(&dir)
        .args(["fleet-status", "--json", "--expiring-within", "60"])
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert!(!stdout(&output).contains("fake-fleet-q8-scoped-5"));

    let report = json_stdout(&output);
    assert_eq!(report["expiring_within_days"], 60);
    // 30 days and 45 days out both read as expiring_soon under a 60-day window.
    assert_eq!(
        secret(&report, "FRESH_API_KEY")["expiry"]["state"],
        "expiring_soon"
    );
    let scoped = secret(&report, "staging/SCOPED_KEY");
    assert_eq!(scoped["environment"], "staging");
    assert_eq!(scoped["expiry"]["state"], "expiring_soon");
}

#[test]
fn fleet_status_strict_exits_2_only_when_something_needs_attention() {
    let dirty = fleet_project();
    for args in [
        &["fleet-status", "--strict"][..],
        &["fleet-status", "--json", "--strict"][..],
        &["--json", "fleet-status", "--strict"][..],
    ] {
        let output = phantom(&dirty).args(args).output().unwrap();
        assert_eq!(code(&output), 2, "{args:?}");
        assert_value_free(&output);
        // The report still prints before the strict exit.
        if args.contains(&"--json") {
            let report = json_stdout(&output);
            assert_eq!(report["needs_attention"], true);
        }
    }

    // A fleet with nothing to act on stays exit 0 under --strict.
    let clean = common::canonical_tempdir();
    phantom(&clean).args(["init", "--empty"]).assert().success();
    let output = phantom(&clean)
        .args(["fleet-status", "--json", "--strict"])
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let report = json_stdout(&output);
    assert_eq!(report["needs_attention"], false);
    assert_eq!(report["summary"]["secrets"], 0);
    assert_eq!(report["overdue_rotations"].as_array().unwrap().len(), 0);
}

#[test]
fn fleet_status_global_json_matches_the_command_flag() {
    let dir = fleet_project();
    let own = phantom(&dir)
        .args(["fleet-status", "--json"])
        .output()
        .unwrap();
    let global = phantom(&dir)
        .args(["--json", "fleet-status"])
        .output()
        .unwrap();
    assert_eq!(code(&own), 0);
    assert_eq!(code(&global), 0);
    // `generated_at` may tick between runs; compare the deterministic parts.
    for key in [
        "secrets",
        "overdue_rotations",
        "summary",
        "inventory",
        "kind",
    ] {
        assert_eq!(json_stdout(&own)[key], json_stdout(&global)[key], "{key}");
    }
}

#[test]
fn fleet_status_human_output_names_secrets_without_values() {
    let dir = fleet_project();
    let output = phantom(&dir)
        .args(["fleet-status"])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_value_free(&output);
    let text = stdout(&output);
    for name in [
        "EXPIRED_TOKEN",
        "FRESH_API_KEY",
        "NEVER_CHECKED",
        "STALE_ROTATION",
    ] {
        assert!(text.contains(name), "{name} missing from human output");
    }
    assert!(text.contains("Fleet Status"));
    assert!(text.contains("need attention"));
}

#[test]
fn fleet_status_fails_before_init_without_touching_values() {
    let dir = common::canonical_tempdir();
    let output = phantom(&dir)
        .args(["fleet-status", "--json"])
        .output()
        .unwrap();
    assert_ne!(code(&output), 0);
    assert_value_free(&output);
    assert!(
        stderr(&output).contains("phantom init"),
        "stderr should point at init: {}",
        stderr(&output)
    );
    assert!(stdout(&output).trim().is_empty());
}
