//! Integration tests for GitHub App issuance (`phantom grant add github-app`)
//! and the `GithubAppManifestFlow` consent engine.
//!
//! Hermetic: the manifest-conversion and installations endpoints are stubbed
//! with `wiremock`; a `MockLoopbackListener` stands in for the (human) redirect;
//! `NoBrowser` opens nothing. The known mock PEM / client-secret / webhook-secret
//! MUST NEVER appear in stdout, stderr, `--json`, or `.phantom.toml`, while the
//! vault DID receive them — the load-bearing assertion of the whole feature.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VAULT_PASS: &str = "test-issuance-passphrase-github-app";
const MOCK_CLIENT_SECRET: &str = "client_secret_MOCK";
const MOCK_WEBHOOK_SECRET: &str = "webhook_secret_MOCK";
const MOCK_CODE: &str = "manifest_code_MOCK";

/// PEM-shaped mock returned by the stubbed manifest-conversion endpoint. NOT a
/// real key; assembled at runtime so no literal `BEGIN … PRIVATE KEY` header is
/// committed to the source tree (avoids tripping secret scanners).
fn mock_pem() -> String {
    let label = "RSA PRIVATE KEY";
    format!("-----BEGIN {label}-----\nMOCKKEYMATERIALdefinitelynotreal\n-----END {label}-----")
}

/// Stub the two GitHub endpoints the manifest flow hits.
async fn start_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/app-manifests/.+/conversions$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": 12345,
            "slug": "phantom-app",
            "client_id": "Iv1.mockclient",
            "client_secret": MOCK_CLIENT_SECRET,
            "pem": mock_pem(),
            "webhook_secret": MOCK_WEBHOOK_SECRET,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/app/installations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{ "id": 987 }])))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manifest_engine_vaults_pem_and_discovers_installations() {
    let server = start_mock().await;
    let base = server.uri();

    let outcome = tokio::task::spawn_blocking(move || {
        use phantom_core::issuance::loopback::MockStateMode;
        use phantom_core::issuance::ConsentEngine;
        use phantom_core::issuance::{
            Endpoints, GithubAppManifestFlow, GithubManifestSpec, IssuanceDeps, IssuanceRequest,
            MockLoopbackListener, NoBrowser,
        };

        // Enable the mock gate for this in-process call (core sees cfg(test)=false
        // as a dependency, so it needs the explicit opt-in).
        std::env::set_var("PHANTOM_ALLOW_MOCK_ISSUANCE", "1");

        let endpoints = Endpoints {
            github_web: base.clone(),
            github_api: base.clone(),
            authorize: String::new(),
            token: String::new(),
            device_code: String::new(),
            overridden: true,
        };
        let http = phantom_core::issuance::build_http_client().unwrap();
        let browser = NoBrowser;
        let loopback = MockLoopbackListener::new(MOCK_CODE, MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &endpoints,
        };
        let req = IssuanceRequest {
            provider: "github-app".to_string(),
            client_id: None,
            client_secret: None,
            scopes: vec![],
            flow: None,
            app_manifest: Some(GithubManifestSpec::least_privilege("phantom-app", None)),
        };
        let out = GithubAppManifestFlow.issue(&req, &deps).unwrap();
        std::env::remove_var("PHANTOM_ALLOW_MOCK_ISSUANCE");
        out
    })
    .await
    .unwrap();

    assert_eq!(outcome.metadata.installation_ids, vec!["987".to_string()]);
    assert_eq!(outcome.metadata.app_id, Some(12345));

    let pem = outcome
        .materials
        .iter()
        .find(|m| m.phm_name == "GITHUB_APP_PEM")
        .expect("PEM material");
    assert!(pem.value.as_str().starts_with("-----BEGIN"));
    assert!(pem.sensitive);

    let cid = outcome
        .materials
        .iter()
        .find(|m| m.phm_name == "GITHUB_APP_CLIENT_ID")
        .expect("client id material");
    assert!(!cid.sensitive, "client id must be non-sensitive");

    assert!(outcome
        .materials
        .iter()
        .any(|m| m.phm_name == "GITHUB_APP_CLIENT_SECRET" && m.sensitive));
    assert!(outcome
        .materials
        .iter()
        .any(|m| m.phm_name == "GITHUB_APP_WEBHOOK_SECRET" && m.sensitive));

    assert_eq!(outcome.rotation_config.provider, "github");
    assert_eq!(
        outcome.rotation_config.api_key_env.as_deref(),
        Some("GITHUB_APP_PEM")
    );
    assert_eq!(outcome.rotation_config.account_id.as_deref(), Some("987"));

    // The redacting Debug never renders the PEM.
    let dbg = format!("{outcome:?}");
    assert!(dbg.contains("[redacted]"));
    assert!(!dbg.contains("MOCKKEYMATERIAL"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_never_leaks_secrets_but_vault_receives_them() {
    let server = start_mock().await;
    let base = server.uri();
    let dir = TempDir::new().unwrap();
    init_empty(&dir);

    let out = {
        let base = base.clone();
        let dir_path = dir.path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let tmp = TempDirRef(dir_path);
            grant_add_at(&tmp, &base, true, false)
        })
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
    for needle in [
        "-----BEGIN",
        "MOCKKEYMATERIAL",
        MOCK_CLIENT_SECRET,
        MOCK_WEBHOOK_SECRET,
    ] {
        assert!(
            !stdout.contains(needle),
            "secret leaked to stdout: {needle}"
        );
        assert!(
            !stderr.contains(needle),
            "secret leaked to stderr: {needle}"
        );
    }

    // ── The vault DID receive the PEM ────────────────────────────────────────
    let revealed = reveal(&dir, "GITHUB_APP_PEM");
    let revealed_out = String::from_utf8_lossy(&revealed.stdout);
    assert!(
        revealed_out.contains("-----BEGIN"),
        "vault should hold the PEM, got: {revealed_out}"
    );

    // ── .phantom.toml holds the rotation block, no secret bytes ──────────────
    let toml = fs::read_to_string(dir.path().join(".phantom.toml")).unwrap();
    assert!(toml.contains("[phantom.secrets.GITHUB_TOKEN.rotation_provider]"));
    assert!(toml.contains("provider = \"github\""));
    assert!(toml.contains("api_key_env = \"GITHUB_APP_PEM\""));
    assert!(!toml.contains("-----BEGIN"));
    assert!(!toml.contains(MOCK_CLIENT_SECRET));
    assert!(!toml.contains(MOCK_WEBHOOK_SECRET));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_add_json_emits_names_never_values() {
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
    assert_eq!(parsed["provider"], "github");
    assert_eq!(parsed["grant_type"], "app-identity");
    assert_eq!(parsed["value_printed"], false);
    let vaulted = parsed["vaulted"].as_array().unwrap();
    assert!(vaulted.iter().any(|v| v == "GITHUB_APP_PEM"));
    assert!(vaulted.iter().any(|v| v == "GITHUB_APP_CLIENT_ID"));

    for needle in [
        "-----BEGIN",
        "MOCKKEYMATERIAL",
        MOCK_CLIENT_SECRET,
        MOCK_WEBHOOK_SECRET,
    ] {
        assert!(
            !stdout.contains(needle),
            "secret leaked into --json: {needle}"
        );
    }
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
    // No partial write: the PEM must be absent from the vault.
    let revealed = reveal(&dir, "GITHUB_APP_PEM");
    assert!(
        !revealed.status.success()
            || !String::from_utf8_lossy(&revealed.stdout).contains("-----BEGIN"),
        "no PEM must be vaulted on a fail-closed issuance"
    );
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
        .env("PHANTOM_GITHUB_API_BASE", base)
        .env("PHANTOM_GITHUB_WEB_BASE", base)
        .env("PHANTOM_ISSUANCE_MOCK_CODE", MOCK_CODE)
        .env_remove("PHANTOM_AUDIT");
    if allow_mock {
        cmd.env("PHANTOM_ALLOW_MOCK_ISSUANCE", "1");
    } else {
        cmd.env_remove("PHANTOM_ALLOW_MOCK_ISSUANCE");
    }
    let mut args = vec!["grant", "add", "github-app"];
    if json {
        args.push("--json");
    }
    cmd.args(&args).output().expect("run phantom grant add")
}
