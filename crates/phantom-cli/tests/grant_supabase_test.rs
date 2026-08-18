//! Integration tests for Supabase OAuth issuance (`phantom grant add supabase`)
//! and the `SupabaseOAuthFlow` consent engine.
//!
//! Hermetic: the OAuth token endpoint is stubbed with `wiremock`; a
//! `MockLoopbackListener` stands in for the (human) redirect; `NoBrowser` opens
//! nothing. The mock refresh token / client secret MUST NEVER appear in stdout,
//! stderr, `--json`, or `.phantom.toml`, while the vault DID receive the refresh
//! token — the load-bearing assertion of the whole feature.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VAULT_PASS: &str = "test-issuance-passphrase-supabase";
const MOCK_REFRESH: &str = "sbrt_refresh_token_MOCK";
const MOCK_ACCESS: &str = "sbat_access_token_MOCK";
const MOCK_CLIENT_SECRET: &str = "sb_client_secret_MOCK";
const MOCK_CODE: &str = "supabase_auth_code_MOCK";

/// Stub the Supabase OAuth token endpoint (authorization_code exchange).
async fn start_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": MOCK_ACCESS,
            "refresh_token": MOCK_REFRESH,
            "token_type": "Bearer",
            "expires_in": 86400,
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

/// Minimal owned `TempDir`-like wrapper so the closure is `Send` for
/// `spawn_blocking`.
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
        // Point the OAuth authorize/token endpoints at the wiremock server.
        .env(
            "PHANTOM_OAUTH_AUTHORIZE_BASE",
            format!("{base}/v1/oauth/authorize"),
        )
        .env("PHANTOM_OAUTH_TOKEN_BASE", format!("{base}/v1/oauth/token"))
        // The deterministic redirect code the MockLoopbackListener returns.
        .env("PHANTOM_ISSUANCE_MOCK_CODE", MOCK_CODE)
        // The confidential client secret, resolved from this env var (never disk).
        .env("SUPA_SECRET", MOCK_CLIENT_SECRET)
        .env_remove("PHANTOM_AUDIT");
    if allow_mock {
        cmd.env("PHANTOM_ALLOW_MOCK_ISSUANCE", "1");
    } else {
        cmd.env_remove("PHANTOM_ALLOW_MOCK_ISSUANCE");
    }
    let mut args = vec![
        "grant",
        "add",
        "supabase",
        "--org",
        "ashlrai",
        "--client-id",
        "sb_client_id",
        "--client-secret-env",
        "SUPA_SECRET",
    ];
    if json {
        args.push("--json");
    }
    cmd.args(&args)
        .output()
        .expect("run phantom grant add supabase")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_supabase_never_leaks_but_vault_receives_refresh_token() {
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
        "grant add supabase failed: stdout={stdout} stderr={stderr}"
    );

    // ── Load-bearing: no secret in ANY output stream ─────────────────────────
    for needle in [MOCK_REFRESH, MOCK_ACCESS, MOCK_CLIENT_SECRET] {
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
    let revealed = reveal(&dir, "SUPABASE_REFRESH_TOKEN");
    let revealed_out = String::from_utf8_lossy(&revealed.stdout);
    assert!(
        revealed_out.contains(MOCK_REFRESH),
        "vault should hold the refresh token"
    );

    // ── .phantom.toml holds the self-rotating management block, no secrets ────
    let toml = fs::read_to_string(dir.path().join(".phantom.toml")).unwrap();
    assert!(toml.contains("[phantom.secrets.SUPABASE_REFRESH_TOKEN.rotation_provider]"));
    assert!(toml.contains("provider = \"supabase-management\""));
    assert!(toml.contains("api_key_env = \"SUPABASE_REFRESH_TOKEN\""));
    assert!(!toml.contains(MOCK_REFRESH));
    assert!(!toml.contains(MOCK_CLIENT_SECRET));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_supabase_json_emits_names_never_values() {
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
    assert!(out.status.success(), "grant add --json failed: {stdout}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON with --json");
    assert_eq!(parsed["state"], "active");
    assert_eq!(parsed["provider"], "supabase");
    assert_eq!(parsed["grant_type"], "oauth-refresh");
    assert_eq!(parsed["value_printed"], false);
    let vaulted = parsed["vaulted"].as_array().unwrap();
    assert!(vaulted.iter().any(|v| v == "SUPABASE_REFRESH_TOKEN"));

    for needle in [MOCK_REFRESH, MOCK_ACCESS, MOCK_CLIENT_SECRET] {
        assert!(
            !stdout.contains(needle),
            "secret leaked into --json: {needle}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_supabase_fails_closed_without_mock_opt_in() {
    let server = start_mock().await;
    let base = server.uri();
    let dir = TempDir::new().unwrap();
    init_empty(&dir);

    let out = {
        let base = base.clone();
        let dir_path = dir.path().to_path_buf();
        // Endpoint override in effect but mock issuance disabled → fail closed
        // before any credential is vaulted.
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
    // No partial write: the refresh token must be absent from the vault.
    let revealed = reveal(&dir, "SUPABASE_REFRESH_TOKEN");
    assert!(
        !revealed.status.success()
            || !String::from_utf8_lossy(&revealed.stdout).contains(MOCK_REFRESH),
        "no refresh token must be vaulted on a fail-closed issuance"
    );
}
