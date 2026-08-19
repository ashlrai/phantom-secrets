//! Integration tests for the Vercel Integration grant
//! (`phantom grant add vercel-integration`) and the `VercelIntegrationFlow`
//! consent engine.
//!
//! Hermetic: the `/v2/oauth/access_token` exchange is stubbed with `wiremock`
//! (reached via the `PHANTOM_OAUTH_TOKEN_BASE` override seam); a
//! `MockLoopbackListener` stands in for the human "Add Integration" redirect;
//! `NoBrowser` opens nothing. The scoped access token MUST NEVER appear in
//! stdout, stderr, `--json`, or `.phantom.toml`, while the vault DID receive it
//! — the load-bearing assertion of the whole feature. teamId (non-secret) DOES
//! land in the rotation block's `account_id`.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VAULT_PASS: &str = "test-issuance-passphrase-vercel-integration";
const MOCK_ACCESS_TOKEN: &str = "vercel_scoped_token_MOCK";
const MOCK_CLIENT_SECRET: &str = "vercel_integration_client_secret_MOCK";
const MOCK_CODE: &str = "vercel_install_code_MOCK";
const MOCK_TEAM: &str = "team_abc123";

/// Stub the one endpoint the Integration flow hits: the code→token exchange.
async fn start_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/oauth/access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": MOCK_ACCESS_TOKEN,
            "token_type": "Bearer",
            "team_id": MOCK_TEAM,
            "installation_id": "icfg_mock",
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

/// Minimal `TempDir`-like wrapper so `grant_add_at` runs inside `spawn_blocking`
/// (which needs an owned, `Send` path).
struct TempDirRef(std::path::PathBuf);
impl TempDirRef {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

fn grant_add_at(
    dir: &TempDirRef,
    token_base: &str,
    allow_mock: bool,
    json: bool,
) -> std::process::Output {
    let mut cmd = Command::cargo_bin("phantom").unwrap();
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        // Point the token exchange at the wiremock; flips endpoints.overridden.
        .env(
            "PHANTOM_OAUTH_TOKEN_BASE",
            format!("{token_base}/v2/oauth/access_token"),
        )
        .env("PHANTOM_ISSUANCE_MOCK_CODE", MOCK_CODE)
        .env("VERCEL_INTEGRATION_SECRET", MOCK_CLIENT_SECRET)
        .env_remove("PHANTOM_AUDIT");
    if allow_mock {
        cmd.env("PHANTOM_ALLOW_MOCK_ISSUANCE", "1");
    } else {
        cmd.env_remove("PHANTOM_ALLOW_MOCK_ISSUANCE");
    }
    let mut args = vec![
        "grant",
        "add",
        "vercel-integration",
        "--client-id",
        "phantom_client_id",
        "--client-secret-env",
        "VERCEL_INTEGRATION_SECRET",
        "--team",
        MOCK_TEAM,
    ];
    if json {
        args.push("--json");
    }
    cmd.args(&args).output().expect("run phantom grant add")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_never_leaks_token_but_vault_receives_it() {
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
        "grant add failed: stdout={stdout} stderr={stderr}"
    );

    // ── Load-bearing: no secret in ANY output stream ─────────────────────────
    for needle in [MOCK_ACCESS_TOKEN, MOCK_CLIENT_SECRET] {
        assert!(
            !stdout.contains(needle),
            "secret leaked to stdout: {needle}"
        );
        assert!(
            !stderr.contains(needle),
            "secret leaked to stderr: {needle}"
        );
    }

    // ── The vault DID receive the scoped token ───────────────────────────────
    let revealed = reveal(&dir, "VERCEL_INTEGRATION_TOKEN");
    let revealed_out = String::from_utf8_lossy(&revealed.stdout);
    assert!(
        revealed_out.contains(MOCK_ACCESS_TOKEN),
        "vault should hold the scoped token, got: {revealed_out}"
    );

    // ── .phantom.toml holds the rotation block + teamId, no token bytes ──────
    let toml = fs::read_to_string(dir.path().join(".phantom.toml")).unwrap();
    assert!(toml.contains("[phantom.secrets.VERCEL_INTEGRATION_TOKEN.rotation_provider]"));
    assert!(toml.contains("provider = \"vercel\""));
    assert!(toml.contains("api_key_env = \"VERCEL_INTEGRATION_TOKEN\""));
    // teamId is NOT a secret — it must be present for team-scoped REST calls.
    assert!(toml.contains(&format!("account_id = \"{MOCK_TEAM}\"")));
    assert!(!toml.contains(MOCK_ACCESS_TOKEN));
    assert!(!toml.contains(MOCK_CLIENT_SECRET));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_json_emits_names_and_team_never_token() {
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
    assert_eq!(parsed["provider"], "vercel");
    assert_eq!(parsed["grant_type"], "app-identity");
    assert_eq!(parsed["value_printed"], false);
    let vaulted = parsed["vaulted"].as_array().unwrap();
    assert!(vaulted.iter().any(|v| v == "VERCEL_INTEGRATION_TOKEN"));
    // teamId surfaces in non-secret metadata.
    assert_eq!(parsed["metadata"]["account"], MOCK_TEAM);

    assert!(
        !stdout.contains(MOCK_ACCESS_TOKEN),
        "token leaked into --json"
    );
    assert!(
        !stdout.contains(MOCK_CLIENT_SECRET),
        "client secret leaked into --json"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_fails_closed_without_mock_opt_in() {
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
    // No partial write: the token must be absent from the vault.
    let revealed = reveal(&dir, "VERCEL_INTEGRATION_TOKEN");
    assert!(
        !revealed.status.success()
            || !String::from_utf8_lossy(&revealed.stdout).contains(MOCK_ACCESS_TOKEN),
        "no token must be vaulted on a fail-closed issuance"
    );
}
