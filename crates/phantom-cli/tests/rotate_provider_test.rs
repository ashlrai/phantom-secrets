/// Integration tests for `phantom rotate --name <KEY> [--provider <VENDOR>]`
/// (real named-secret rotation via a vendor rotation provider).
///
/// These tests use the providers' hermetic mock fast paths (bootstrap
/// credentials with the `sk_test_mock_` prefix) — no network calls are made
/// and no real credentials exist anywhere in this file. The fixed fake value
/// the mock path stores in the vault is known, which lets the tests assert
/// the CLI NEVER prints the stored value to stdout or stderr.
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "test-integration-passphrase-rotate-provider";

/// The fixed fake value the Stripe mock finalize path stores in the vault
/// (see `StripeRotationProvider::finalize_rotation` in phantom-core).
const MOCK_ROTATED_VALUE: &str = "sk_test_rotated_mock_value_stripe";

fn init_project(dir: &TempDir) {
    // Seed .env with a value phantom's heuristics flag as a secret.
    fs::write(
        dir.path().join(".env"),
        "STRIPE_SECRET_KEY=sk-seed-stripe-value\n",
    )
    .expect("write seed .env");

    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["init", "--from", ".env"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();

    // Configure a rotation provider for the secret, exactly as an operator
    // would in .phantom.toml.
    let config_path = dir.path().join(".phantom.toml");
    let mut config = fs::read_to_string(&config_path).expect("read .phantom.toml");
    config.push_str(
        "\n[phantom.secrets.STRIPE_SECRET_KEY.rotation_provider]\n\
         provider = \"stripe\"\n\
         api_key_env = \"STRIPE_ROTATION_ADMIN_KEY\"\n",
    );
    fs::write(&config_path, config).expect("write .phantom.toml");
}

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        // Mock provider fast-paths are fail-closed in shipped binaries and
        // require this explicit test-only opt-in.
        .env("PHANTOM_ALLOW_MOCK_ROTATION", "1")
        .env_remove("PHANTOM_AUDIT")
        .env_remove("STRIPE_ROTATION_ADMIN_KEY");
    cmd
}

#[test]
fn rotate_provider_stores_value_without_printing_it() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // Bootstrap credential in the environment; mock prefix keeps it hermetic.
    let output = phantom(&dir)
        .args([
            "rotate",
            "--provider",
            "stripe",
            "--name",
            "STRIPE_SECRET_KEY",
        ])
        .env("STRIPE_ROTATION_ADMIN_KEY", "sk_test_mock_env_bootstrap")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    // The value written to the vault must NEVER surface in any output stream.
    assert!(
        !combined.contains(MOCK_ROTATED_VALUE),
        "rotated secret value leaked into CLI output"
    );
    // Neither may the bootstrap credential.
    assert!(
        !combined.contains("sk_test_mock_env_bootstrap"),
        "bootstrap credential leaked into CLI output"
    );
    // Metadata-only success message.
    assert!(
        stdout.contains("stored in the vault"),
        "expected success metadata, got: {stdout}"
    );
    assert!(
        stdout.contains("not printed"),
        "expected value-withheld notice, got: {stdout}"
    );

    // The .env phm_ token must have been refreshed — and must not contain
    // the rotated value either.
    let env_content = fs::read_to_string(dir.path().join(".env")).expect("read .env");
    assert!(
        env_content.contains("STRIPE_SECRET_KEY=phm_"),
        ".env must keep a phantom token, got: {env_content}"
    );
    assert!(
        !env_content.contains(MOCK_ROTATED_VALUE),
        "rotated secret value leaked into .env"
    );
}

#[test]
fn rotate_provider_json_emits_metadata_only() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    let output = phantom(&dir)
        .args([
            "rotate",
            "--provider",
            "stripe",
            "--name",
            "STRIPE_SECRET_KEY",
            "--json",
        ])
        .env("STRIPE_ROTATION_ADMIN_KEY", "sk_test_mock_json_bootstrap")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout).to_string();

    // The whole stdout must parse as one JSON object (scripting contract).
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON with --json");

    assert_eq!(parsed["secret"], "STRIPE_SECRET_KEY");
    assert_eq!(parsed["provider"], "stripe");
    assert_eq!(parsed["status"], "rotated");
    assert_eq!(parsed["vendor_rotated"], true);
    assert_eq!(parsed["stored_in_vault"], true);
    assert_eq!(parsed["value_printed"], false);
    assert!(
        parsed.get("expires_at").is_some(),
        "JSON must carry an expires_at field (null when no TTL)"
    );

    // No secret material anywhere in the JSON.
    assert!(
        !stdout.contains(MOCK_ROTATED_VALUE),
        "rotated secret value leaked into --json output"
    );
    assert!(
        !stdout.contains("sk_test_mock_json_bootstrap"),
        "bootstrap credential leaked into --json output"
    );
}

#[test]
fn rotate_provider_resolves_provider_and_bootstrap_from_config_and_vault() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // Store the bootstrap credential in the VAULT under the api_key_env name
    // — no environment variable is set for it in this test.
    phantom(&dir)
        .args(["add", "STRIPE_ROTATION_ADMIN_KEY", "--stdin"])
        .write_stdin("sk_test_mock_vault_bootstrap\n")
        .assert()
        .success();

    // No --provider flag: resolved from .phantom.toml. No env var: bootstrap
    // sourced from the vault.
    let output = phantom(&dir)
        .args(["rotate", "--name", "STRIPE_SECRET_KEY"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    assert!(
        stdout.contains("stripe"),
        "provider resolved from config must be reported, got: {stdout}"
    );
    assert!(
        stdout.contains("stored in the vault"),
        "expected success metadata, got: {stdout}"
    );
    assert!(
        !combined.contains(MOCK_ROTATED_VALUE),
        "rotated secret value leaked into CLI output"
    );
    assert!(
        !combined.contains("sk_test_mock_vault_bootstrap"),
        "vault-sourced bootstrap credential leaked into CLI output"
    );
}

#[test]
fn rotate_provider_mock_bootstrap_fails_closed_without_opt_in() {
    // Regression: a mock-prefixed bootstrap credential must NOT drive a forged
    // "successful" rotation in a production binary — it requires the explicit
    // PHANTOM_ALLOW_MOCK_ROTATION=1 opt-in.
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    let output = phantom(&dir)
        .args([
            "rotate",
            "--provider",
            "stripe",
            "--name",
            "STRIPE_SECRET_KEY",
        ])
        .env_remove("PHANTOM_ALLOW_MOCK_ROTATION")
        .env("STRIPE_ROTATION_ADMIN_KEY", "sk_test_mock_no_opt_in")
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&output.get_output().stderr).to_string();
    assert!(
        stderr.contains("mock"),
        "error must explain the mock path is disabled, got: {stderr}"
    );
    assert!(
        !stderr.contains("sk_test_mock_no_opt_in"),
        "bootstrap credential leaked into CLI error output"
    );
}

#[test]
fn rotate_provider_disabled_config_reports_disabled_not_bad_credential() {
    // Regression: enabled = false must surface as a distinct "disabled" error,
    // never the misleading api_key_env / bootstrap-credential message.
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    let config_path = dir.path().join(".phantom.toml");
    let mut config = fs::read_to_string(&config_path).expect("read .phantom.toml");
    config.push_str("enabled = false\n");
    fs::write(&config_path, config).expect("write .phantom.toml");

    let output = phantom(&dir)
        .args(["rotate", "--name", "STRIPE_SECRET_KEY"])
        .env("STRIPE_ROTATION_ADMIN_KEY", "sk_test_mock_disabled")
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&output.get_output().stderr).to_string();
    assert!(
        stderr.contains("disabled"),
        "error must say the provider is disabled, got: {stderr}"
    );
    assert!(
        !stderr.contains("api_key_env resolves"),
        "disabled config must not be blamed on the bootstrap credential: {stderr}"
    );
}

#[test]
fn rotate_provider_dispatches_by_config_not_secret_name() {
    // Regression: a secret whose name contains no vendor substring must still
    // rotate via the provider configured in .phantom.toml.
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join(".env"),
        "PAYMENTS_API_KEY=sk-seed-payments-value\n",
    )
    .expect("write seed .env");

    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["init", "--from", ".env"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();

    let config_path = dir.path().join(".phantom.toml");
    let mut config = fs::read_to_string(&config_path).expect("read .phantom.toml");
    config.push_str(
        "\n[phantom.secrets.PAYMENTS_API_KEY.rotation_provider]\n\
         provider = \"stripe\"\n\
         api_key_env = \"STRIPE_ROTATION_ADMIN_KEY\"\n",
    );
    fs::write(&config_path, config).expect("write .phantom.toml");

    let output = phantom(&dir)
        .args(["rotate", "--name", "PAYMENTS_API_KEY", "--json"])
        .env("STRIPE_ROTATION_ADMIN_KEY", "sk_test_mock_dispatch_cfg")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout).to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    assert_eq!(parsed["secret"], "PAYMENTS_API_KEY");
    assert_eq!(parsed["provider"], "stripe");
    assert_eq!(parsed["status"], "rotated");
}

#[test]
fn rotate_provider_mismatch_with_config_fails() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    // Config says stripe; requesting github must fail with guidance.
    let output = phantom(&dir)
        .args([
            "rotate",
            "--provider",
            "github",
            "--name",
            "STRIPE_SECRET_KEY",
        ])
        .env("STRIPE_ROTATION_ADMIN_KEY", "sk_test_mock_mismatch")
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&output.get_output().stderr).to_string();
    assert!(
        stderr.contains("configured for provider 'stripe'"),
        "mismatch error must name the configured provider, got: {stderr}"
    );
}

#[test]
fn rotate_name_without_config_fails_with_toml_guidance() {
    let dir = TempDir::new().unwrap();

    // Project with a vaulted secret but NO rotation_provider block.
    fs::write(dir.path().join(".env"), "OTHER_API_KEY=sk-other-value\n").expect("write .env");
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["init", "--from", ".env"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();

    let output = phantom(&dir)
        .args(["rotate", "--name", "OTHER_API_KEY"])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&output.get_output().stderr).to_string();
    assert!(
        stderr.contains("rotation_provider"),
        "error must point at the missing config block, got: {stderr}"
    );
    assert!(
        stderr.contains("[phantom.secrets.OTHER_API_KEY.rotation_provider]"),
        "error must include a copy-pasteable TOML snippet, got: {stderr}"
    );
}
