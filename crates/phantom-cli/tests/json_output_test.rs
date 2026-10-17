//! `--json` modes keep stdout a single parseable JSON document, including the
//! empty and not-found cases where a human hint would otherwise appear.
mod common;

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

fn phantom(project: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_phantom"))
        .args(args)
        .current_dir(project)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("NO_COLOR", "1")
        .env_remove("PHANTOM_AUDIT")
        .env_remove("PHANTOM_VAULT_PASSPHRASE")
        .output()
        .unwrap()
}

fn stdout_json(output: &Output) -> Value {
    assert!(output.status.success(), "command failed: {output:?}");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON ({error}): {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn audit_stats_json_with_empty_log_is_json() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let report = stdout_json(&phantom(
        project.path(),
        home.path(),
        &["audit", "stats", "--json"],
    ));
    assert_eq!(report["total_events"], 0);
    assert_eq!(report["secret_events"], 0);
    assert!(report["first_event_ts"].is_null());
    assert!(report["last_event_ts"].is_null());
    assert_eq!(report["secrets"], serde_json::json!([]));
}

#[test]
fn audit_export_json_with_no_records_is_empty_array() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let output = phantom(
        project.path(),
        home.path(),
        &["audit", "export", "--format", "json"],
    );
    assert_eq!(stdout_json(&output), serde_json::json!([]));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No access records"));
}

#[test]
fn why_json_reports_classification_without_values() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let secret_value = concat!("rk", "_placeholder_value_abcdefghijklmnop");
    std::fs::write(
        project.path().join(".env"),
        format!("STRIPE_SECRET_KEY={secret_value}\nNODE_ENV=production\n"),
    )
    .unwrap();

    let output = phantom(
        project.path(),
        home.path(),
        &["why", "STRIPE_SECRET_KEY", "--json"],
    );
    let report = stdout_json(&output);
    assert_eq!(report["key"], "STRIPE_SECRET_KEY");
    assert_eq!(report["found"], true);
    assert_eq!(report["protected"], false);
    assert_eq!(report["classification"], "secret_unprotected");
    assert_eq!(report["reason"], "key_name");
    assert!(report["service"].is_null());
    assert!(report["next_step"]
        .as_str()
        .unwrap()
        .contains("phantom init"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret_value));

    let not_secret = stdout_json(&phantom(
        project.path(),
        home.path(),
        &["--json", "why", "NODE_ENV"],
    ));
    assert_eq!(not_secret["classification"], "not_secret");

    let missing = stdout_json(&phantom(
        project.path(),
        home.path(),
        &["why", "NOPE", "--json"],
    ));
    assert_eq!(missing["found"], false);
    assert_eq!(missing["dotenv_exists"], true);
    assert!(missing["next_step"].is_string());
}

#[test]
fn why_json_without_dotenv_is_json_and_human_output_is_unchanged() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let report = stdout_json(&phantom(
        project.path(),
        home.path(),
        &["why", "OPENAI_API_KEY", "--json"],
    ));
    assert_eq!(report["found"], false);
    assert_eq!(report["dotenv_exists"], false);

    // Without --json the missing-.env case stays an error.
    let human = phantom(project.path(), home.path(), &["why", "OPENAI_API_KEY"]);
    assert!(!human.status.success());
    assert!(String::from_utf8_lossy(&human.stderr).contains("No .env file found"));

    std::fs::write(project.path().join(".env"), "NODE_ENV=production\n").unwrap();
    let human = phantom(project.path(), home.path(), &["why", "NODE_ENV"]);
    assert!(human.status.success());
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(
        text.contains("NODE_ENV is NOT PROTECTED (non-secret config)"),
        "{text}"
    );
}
