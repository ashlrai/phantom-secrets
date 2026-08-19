//! Integration tests for Stripe App OAuth issuance (`phantom grant add stripe`)
//! and the fail-closed restricted-key path.
//!
//! Hermetic: the `POST /v1/oauth/token` exchange is stubbed with `wiremock`; a
//! `MockLoopbackListener` (via `PHANTOM_ISSUANCE_MOCK_CODE`) stands in for the
//! human "accept permissions" redirect; `NoBrowser` opens nothing. The mock
//! refresh token and the developer secret key MUST NEVER appear in stdout,
//! stderr, `--json`, or `.phantom.toml`, while the vault DID receive the refresh
//! token — the load-bearing assertion of the whole feature.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VAULT_PASS: &str = "test-issuance-passphrase-stripe";
const MOCK_REFRESH: &str = "rt_test_refresh_MOCK";
const MOCK_ACCESS: &str = "sk_test_access_MOCK";
const DEV_SECRET: &str = "sk_test_developer_MOCK";
const MOCK_CODE: &str = "ac_stripe_code_MOCK";

/// Stub the Stripe OAuth token endpoint.
async fn start_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": MOCK_ACCESS,
            "refresh_token": MOCK_REFRESH,
            "stripe_user_id": "acct_MOCK123",
            "stripe_publishable_key": "pk_test_MOCK",
            "scope": "read_write",
            "livemode": false,
            "token_type": "bearer",
        })))
        .mount(&server)
        .await;
    server
}

fn init_empty(dir: &TempDir) {
    Command::cargo_bin("phantom")
        .unwrap()
        .args(["init", "--empty"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();
}

fn reveal(dir: &TempDir, name: &str) -> std::process::Output {
    Command::cargo_bin("phantom")
        .unwrap()
        .args(["reveal", name, "--yes"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .output()
        .expect("run phantom reveal")
}

/// Minimal `TempDir`-like wrapper so `grant_add_at` can run inside
/// `spawn_blocking` (which needs an owned, `Send` path).
struct TempDirRef(std::path::PathBuf);
impl TempDirRef {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

fn grant_add_at(
    dir: &TempDirRef,
    base: &str,
    allow_mock: bool,
    extra_args: &[&str],
) -> std::process::Output {
    let mut cmd = Command::cargo_bin("phantom").unwrap();
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .env(
            "PHANTOM_OAUTH_AUTHORIZE_BASE",
            format!("{base}/oauth/authorize"),
        )
        .env("PHANTOM_OAUTH_TOKEN_BASE", format!("{base}/v1/oauth/token"))
        .env("PHANTOM_ISSUANCE_MOCK_CODE", MOCK_CODE)
        .env("STRIPE_APP_SECRET_KEY", DEV_SECRET)
        .env_remove("PHANTOM_AUDIT");
    if allow_mock {
        cmd.env("PHANTOM_ALLOW_MOCK_ISSUANCE", "1");
    } else {
        cmd.env_remove("PHANTOM_ALLOW_MOCK_ISSUANCE");
    }
    let mut args = vec!["grant", "add", "stripe", "--client-id", "ca_phantom_app"];
    args.extend_from_slice(extra_args);
    cmd.args(&args)
        .output()
        .expect("run phantom grant add stripe")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_stripe_never_leaks_but_vault_receives_refresh_token() {
    let server = start_mock().await;
    let base = server.uri();
    let dir = TempDir::new().unwrap();
    init_empty(&dir);

    let out = {
        let base = base.clone();
        let dir_path = dir.path().to_path_buf();
        tokio::task::spawn_blocking(move || grant_add_at(&TempDirRef(dir_path), &base, true, &[]))
            .await
            .unwrap()
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "grant add stripe failed: stdout={stdout} stderr={stderr}"
    );

    // ── Load-bearing: no secret in ANY output stream ─────────────────────────
    for needle in [MOCK_REFRESH, MOCK_ACCESS, DEV_SECRET] {
        assert!(
            !stdout.contains(needle),
            "secret leaked to stdout: {needle}"
        );
        assert!(
            !stderr.contains(needle),
            "secret leaked to stderr: {needle}"
        );
    }

    // ── The vault DID receive the refresh token ──────────────────────────────
    let revealed = reveal(&dir, "STRIPE_REFRESH_TOKEN");
    let revealed_out = String::from_utf8_lossy(&revealed.stdout);
    assert!(
        revealed_out.contains(MOCK_REFRESH),
        "vault should hold the refresh token, got: {revealed_out}"
    );

    // ── .phantom.toml holds the rotation block, no secret bytes ──────────────
    let toml = fs::read_to_string(dir.path().join(".phantom.toml")).unwrap();
    assert!(toml.contains("[phantom.secrets.STRIPE_REFRESH_TOKEN.rotation_provider]"));
    assert!(toml.contains("provider = \"stripe\""));
    assert!(toml.contains("api_key_env = \"STRIPE_REFRESH_TOKEN\""));
    assert!(!toml.contains(MOCK_REFRESH));
    assert!(!toml.contains(DEV_SECRET));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_stripe_json_emits_names_never_values() {
    let server = start_mock().await;
    let base = server.uri();
    let dir = TempDir::new().unwrap();
    init_empty(&dir);

    let out = {
        let base = base.clone();
        let dir_path = dir.path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            grant_add_at(&TempDirRef(dir_path), &base, true, &["--json"])
        })
        .await
        .unwrap()
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "grant add stripe --json failed: {stdout}"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON with --json");
    assert_eq!(parsed["state"], "active");
    assert_eq!(parsed["provider"], "stripe");
    assert_eq!(parsed["grant_type"], "oauth-refresh");
    assert_eq!(parsed["value_printed"], false);
    let vaulted = parsed["vaulted"].as_array().unwrap();
    assert!(vaulted.iter().any(|v| v == "STRIPE_REFRESH_TOKEN"));

    for needle in [MOCK_REFRESH, MOCK_ACCESS, DEV_SECRET] {
        assert!(
            !stdout.contains(needle),
            "secret leaked into --json: {needle}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_stripe_fails_closed_without_mock_opt_in() {
    let server = start_mock().await;
    let base = server.uri();
    let dir = TempDir::new().unwrap();
    init_empty(&dir);

    let out = {
        let base = base.clone();
        let dir_path = dir.path().to_path_buf();
        // Endpoint override in effect but mock issuance disabled → fail closed
        // before any credential is vaulted.
        tokio::task::spawn_blocking(move || grant_add_at(&TempDirRef(dir_path), &base, false, &[]))
            .await
            .unwrap()
    };

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must fail closed without opt-in");
    assert!(
        stderr.to_lowercase().contains("mock"),
        "error must explain the mock path is disabled, got: {stderr}"
    );
    // No partial write: the refresh token must be absent from the vault.
    let revealed = reveal(&dir, "STRIPE_REFRESH_TOKEN");
    assert!(
        !revealed.status.success()
            || !String::from_utf8_lossy(&revealed.stdout).contains(MOCK_REFRESH),
        "no refresh token must be vaulted on a fail-closed issuance"
    );
}

#[test]
fn grant_add_stripe_restricted_key_is_not_supported_with_dashboard_link() {
    // The RAK path takes no network and needs no mock server: it refuses with a
    // dashboard link and recommends the OAuth flow (STRIPE_KOALA_TEST guidance).
    let dir = TempDir::new().unwrap();
    init_empty(&dir);

    let out = Command::cargo_bin("phantom")
        .unwrap()
        .args(["grant", "add", "stripe", "--flow", "rak"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .env_remove("PHANTOM_AUDIT")
        .output()
        .expect("run phantom grant add stripe --flow rak");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the RAK path must be NotSupported");
    assert!(
        stderr.contains("dashboard.stripe.com"),
        "must point at the sandbox dashboard, got: {stderr}"
    );
    assert!(
        stderr.contains("grant add stripe"),
        "must recommend the OAuth route, got: {stderr}"
    );
}
