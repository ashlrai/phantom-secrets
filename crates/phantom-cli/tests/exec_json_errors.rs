//! The exec error envelope never includes repository-controlled diagnostics.
use std::process::Command;

fn refusal(config: Option<&str>, dotenv: Option<&str>, expected: &str) {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    if let Some(config) = config {
        std::fs::write(project.path().join(".phantom.toml"), config).unwrap();
    }
    if let Some(dotenv) = dotenv {
        std::fs::write(project.path().join(".env"), dotenv).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
        .current_dir(project.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env(
            "PHANTOM_VAULT_PASSPHRASE",
            "synthetic-json-error-test-passphrase",
        )
        .args(["exec", "--json", "--", "never-launch-this-command"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(report["schema"], "phantom.exec.error.v1");
    assert_eq!(report["error"]["code"], expected);
    assert_eq!(report.as_object().unwrap().len(), 2);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("never-launch-this-command"));
}

#[test]
fn uninitialized_exec_has_a_value_free_json_error() {
    refusal(None, None, "exec_failed");
}

#[test]
fn unknown_route_is_classified_before_vault_access() {
    refusal(
        Some("[phantom]\nversion = '0.7.9'\nproject_id = 'json-test'\n[services.unapproved]\nsecret_key = 'CUSTOM_KEY'\npattern = 'unapproved.invalid'\n"),
        None,
        "unknown_route",
    );
}

#[test]
fn protected_state_without_placeholders_is_classified() {
    refusal(
        Some("[phantom]\nversion = '0.7.9'\nproject_id = 'json-test'\ndotenv_path = '.env'\n[phantom.secrets.OPENAI_API_KEY]\n"),
        Some("PUBLIC_SETTING=example\n"),
        "placeholder_mismatch",
    );
}

#[test]
fn missing_secret_is_classified_without_exposing_the_placeholder() {
    let token = phantom_core::token::PhantomToken::generate();
    refusal(
        Some("[phantom]\nversion = '0.7.9'\nproject_id = 'json-test'\ndotenv_path = '.env'\n[phantom.secrets.OPENAI_API_KEY]\n"),
        Some(&format!("OPENAI_API_KEY={}\n", token.as_str())),
        "missing_secret",
    );
}
