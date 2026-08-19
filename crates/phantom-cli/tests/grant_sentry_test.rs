//! Integration tests for Sentry issuance (`phantom grant add sentry`) and the
//! [`SentryInstallFlow`](phantom_core::issuance::SentryInstallFlow) consent
//! engine.
//!
//! Hermetic: the installation-authorizations endpoint is stubbed with
//! `wiremock`; a `MockLoopbackListener` (driven by env) stands in for the human
//! "Accept & Install" redirect, supplying the `installationId`; `NoBrowser`
//! opens nothing. The mock org token / client secret MUST NEVER appear in
//! stdout, stderr, `--json`, or `.phantom.toml`, while the vault DID receive
//! them — the load-bearing assertion of the whole feature.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VAULT_PASS: &str = "test-issuance-passphrase-sentry";
const MOCK_CLIENT_SECRET: &str = "sentry_client_secret_MOCK";
const MOCK_ORG_TOKEN: &str = "sntrys_orgtoken_MOCK";
const MOCK_REFRESH: &str = "sntrys_refresh_MOCK";
const MOCK_CODE: &str = "sentry_install_code_MOCK";
const MOCK_INSTALL_UUID: &str = "install-uuid-mock-1234";
const SECRET_ENV: &str = "PHANTOM_TEST_SENTRY_CLIENT_SECRET";

/// Stub the installation authorization exchange for any installation uuid.
async fn start_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(
            r"^/api/0/sentry-app-installations/.+/authorizations/$",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": MOCK_ORG_TOKEN,
            "refreshToken": MOCK_REFRESH,
            "expiresAt": "2026-01-01T00:00:00Z",
            "scopes": ["org:read", "project:read"],
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
    json: bool,
) -> std::process::Output {
    let mut cmd = Command::cargo_bin("phantom").unwrap();
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        // The whole Sentry flow derives its API origin from the OAuth token
        // endpoint, so this single override repoints the exchange at wiremock.
        .env("PHANTOM_OAUTH_TOKEN_BASE", format!("{base}/oauth/token/"))
        .env("PHANTOM_ISSUANCE_MOCK_CODE", MOCK_CODE)
        .env("PHANTOM_ISSUANCE_MOCK_INSTALLATION_ID", MOCK_INSTALL_UUID)
        .env(SECRET_ENV, MOCK_CLIENT_SECRET)
        .env_remove("PHANTOM_AUDIT");
    if allow_mock {
        cmd.env("PHANTOM_ALLOW_MOCK_ISSUANCE", "1");
    } else {
        cmd.env_remove("PHANTOM_ALLOW_MOCK_ISSUANCE");
    }
    let mut args = vec![
        "grant",
        "add",
        "sentry",
        "--client-id",
        "phantom_sentry_client",
        "--client-secret-env",
        SECRET_ENV,
        "--org",
        "phantom",
    ];
    if json {
        args.push("--json");
    }
    cmd.args(&args)
        .output()
        .expect("run phantom grant add sentry")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_sentry_never_leaks_secrets_but_vault_receives_them() {
    let server = start_mock().await;
    let base = server.uri();
    let dir = TempDir::new().unwrap();
    init_empty(&dir);

    let out = {
        let base = base.clone();
        let dir_path = dir.path().to_path_buf();
        tokio::task::spawn_blocking(move || grant_add_at(&TempDirRef(dir_path), &base, true, false))
            .await
            .unwrap()
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "grant add sentry failed: stdout={stdout} stderr={stderr}"
    );

    // ── Load-bearing: no secret in ANY output stream ─────────────────────────
    for needle in [MOCK_CLIENT_SECRET, MOCK_ORG_TOKEN, MOCK_REFRESH] {
        assert!(
            !stdout.contains(needle),
            "secret leaked to stdout: {needle}"
        );
        assert!(
            !stderr.contains(needle),
            "secret leaked to stderr: {needle}"
        );
    }

    // ── The vault DID receive the org token + the app-identity seed ──────────
    let token = reveal(&dir, "SENTRY_ORG_TOKEN");
    assert!(
        String::from_utf8_lossy(&token.stdout).contains(MOCK_ORG_TOKEN),
        "vault should hold the minted org token"
    );
    let seed = reveal(&dir, "SENTRY_APP_JWT_SEED");
    assert!(
        String::from_utf8_lossy(&seed.stdout).contains(MOCK_CLIENT_SECRET),
        "vault should hold the app-identity seed (embedding the client secret)"
    );

    // ── .phantom.toml holds the rotation block, no secret bytes ──────────────
    let toml = fs::read_to_string(dir.path().join(".phantom.toml")).unwrap();
    assert!(toml.contains("[phantom.secrets.SENTRY_ORG_TOKEN.rotation_provider]"));
    assert!(toml.contains("provider = \"sentry\""));
    assert!(toml.contains("api_key_env = \"SENTRY_APP_JWT_SEED\""));
    assert!(
        toml.contains(MOCK_INSTALL_UUID),
        "the installation uuid is recorded as the rotation account_id"
    );
    assert!(!toml.contains(MOCK_CLIENT_SECRET));
    assert!(!toml.contains(MOCK_ORG_TOKEN));
    assert!(!toml.contains(MOCK_REFRESH));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_sentry_json_emits_names_never_values() {
    let server = start_mock().await;
    let base = server.uri();
    let dir = TempDir::new().unwrap();
    init_empty(&dir);

    let out = {
        let base = base.clone();
        let dir_path = dir.path().to_path_buf();
        tokio::task::spawn_blocking(move || grant_add_at(&TempDirRef(dir_path), &base, true, true))
            .await
            .unwrap()
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "grant add sentry --json failed: {stdout}"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON with --json");
    assert_eq!(parsed["state"], "active");
    assert_eq!(parsed["provider"], "sentry");
    assert_eq!(parsed["grant_type"], "app-identity");
    assert_eq!(parsed["value_printed"], false);
    let vaulted = parsed["vaulted"].as_array().unwrap();
    assert!(vaulted.iter().any(|v| v == "SENTRY_APP_JWT_SEED"));
    assert!(vaulted.iter().any(|v| v == "SENTRY_ORG_TOKEN"));

    for needle in [MOCK_CLIENT_SECRET, MOCK_ORG_TOKEN, MOCK_REFRESH] {
        assert!(
            !stdout.contains(needle),
            "secret leaked into --json: {needle}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_sentry_fails_closed_without_mock_opt_in() {
    let server = start_mock().await;
    let base = server.uri();
    let dir = TempDir::new().unwrap();
    init_empty(&dir);

    let out = {
        let base = base.clone();
        let dir_path = dir.path().to_path_buf();
        // allow_mock = false → the endpoint override is in effect but mock
        // issuance is disabled → fail closed before any credential is vaulted.
        tokio::task::spawn_blocking(move || {
            grant_add_at(&TempDirRef(dir_path), &base, false, false)
        })
        .await
        .unwrap()
    };

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must fail closed without opt-in");
    assert!(
        stderr.to_lowercase().contains("mock"),
        "error must explain the mock path is disabled, got: {stderr}"
    );
    // No partial write: the org token must be absent from the vault.
    let revealed = reveal(&dir, "SENTRY_ORG_TOKEN");
    assert!(
        !revealed.status.success()
            || !String::from_utf8_lossy(&revealed.stdout).contains(MOCK_ORG_TOKEN),
        "no org token must be vaulted on a fail-closed issuance"
    );
}
