//! `phantom exec --refs-only`: the session serves exactly the names passed as
//! `NAME=secret://NAME`. Runs exec's real vault, session, child and proxy
//! lifecycle with two trusted routes pointed at a loopback mock. Both names
//! are protected in the dotenv; only GITHUB_TOKEN is referenced.
//!
//! Values are synthetic and match no credential shape. Assertions never print
//! captured output or values.
use super::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use wiremock::{Mock, MockServer, ResponseTemplate};

const FIXTURE: &str = "PHANTOM_REFS_ONLY_EXEC_FIXTURE";
const CHILD: &str = "commands::exec::refs_only_tests::refs_only_client";
const RUNNER: &str = "commands::exec::refs_only_tests::refs_only_fixture";
const REFERENCED: &str = "refs-only-referenced-disposable-value";
const UNREFERENCED: &str = "refs-only-unreferenced-disposable-value";
const MODE_FILE: &str = "refs-only-mode";

#[test]
fn refs_only_lifecycle_loopback() {
    let root = std::env::temp_dir().canonicalize().unwrap();
    let project = tempfile::tempdir_in(&root).unwrap();
    let home = tempfile::tempdir_in(&root).unwrap();
    let mut fixture = Command::new(std::env::current_exe().unwrap())
        .args([RUNNER, "--exact", "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env(
            "PHANTOM_VAULT_PASSPHRASE",
            "refs-only-disposable-passphrase",
        )
        .env("PHANTOM_PROXY_HEADER_AUTH_ONLY", "1")
        .env("GITHUB_TOKEN", "secret://GITHUB_TOKEN")
        .env("NO_COLOR", "1")
        .env(FIXTURE, "1")
        .current_dir(project.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while fixture.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = fixture.kill();
            let _ = fixture.wait();
            panic!("refs-only fixture exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = fixture.wait_with_output().unwrap();
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(REFERENCED),
            "referenced value escaped into output"
        );
        assert!(
            !text.contains(UNREFERENCED),
            "unreferenced value escaped into output"
        );
    }
    assert!(output.status.success(), "refs-only fixture failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("refs-only verified"));
    assert!(stdout.contains("default verified"));
}

async fn mock_upstream() -> MockServer {
    let mock = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock)
        .await;
    mock
}

fn loopback_registry(config: &PhantomConfig, uri: &str) -> ServiceRegistry {
    let canonical = ServiceRegistry::from_config(&config.services);
    let mut registry = ServiceRegistry::new();
    for (_, route) in canonical.services() {
        let mut route = route.clone();
        route.target_base = uri.to_string();
        registry.add_route(route);
    }
    registry
}

/// Upstream credentials seen by the mock, as (path, header value) pairs.
async fn upstream_auth(mock: &MockServer) -> Vec<(String, String)> {
    mock.received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            let auth = ["authorization", "x-api-key"]
                .iter()
                .find_map(|name| request.headers.get(*name))
                .map(|value| value.to_str().unwrap_or_default().to_string())
                .unwrap_or_default();
            (request.url.path().to_string(), auth)
        })
        .collect()
}

#[test]
fn refs_only_fixture() {
    if std::env::var(FIXTURE).as_deref() != Ok("1") {
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut config = PhantomConfig::new_with_defaults("refs-only-exec-fixture".to_string());
        config.services.clear();
        for name in ["github_api", "openai"] {
            config.services.insert(
                name.into(),
                PhantomConfig::trusted_builtin_proxy_service(name).unwrap(),
            );
        }
        config.save(Path::new(".phantom.toml")).unwrap();
        let config = PhantomConfig::load(Path::new(".phantom.toml")).unwrap();
        std::fs::write(
            ".env",
            format!(
                "GITHUB_TOKEN={}\nOPENAI_API_KEY={}\n",
                PhantomToken::generate().as_str(),
                PhantomToken::generate().as_str()
            ),
        )
        .unwrap();
        let vault = phantom_vault::try_create_vault(config.local_project_id()).unwrap();
        vault.store("GITHUB_TOKEN", REFERENCED).unwrap();
        vault.store("OPENAI_API_KEY", UNREFERENCED).unwrap();
        let command = vec![
            std::env::current_exe()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
            CHILD.to_string(),
            "--exact".to_string(),
            "--nocapture".to_string(),
        ];

        // --refs-only: only the referenced route reaches upstream.
        std::fs::write(MODE_FILE, "refs-only").unwrap();
        let mock = mock_upstream().await;
        super::run_async(&command, None, None, true, false, true, |config| {
            loopback_registry(config, &mock.uri())
        })
        .await
        .unwrap();
        let seen = upstream_auth(&mock).await;
        assert_eq!(
            seen.len(),
            1,
            "refs-only sent an unexpected upstream request"
        );
        assert!(seen[0].0.starts_with("/user"));
        assert!(seen[0].1 == format!("Bearer {REFERENCED}"));
        assert!(
            seen.iter().all(|(_, auth)| !auth.contains(UNREFERENCED)),
            "an unreferenced value was injected"
        );

        // Without the flag, behavior is unchanged: both dotenv names are served.
        std::fs::write(MODE_FILE, "default").unwrap();
        let mock = mock_upstream().await;
        super::run_async(&command, None, None, true, false, false, |config| {
            loopback_registry(config, &mock.uri())
        })
        .await
        .unwrap();
        let mut seen = upstream_auth(&mock).await;
        seen.sort();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].0.starts_with("/user") && seen[0].1 == format!("Bearer {REFERENCED}"));
        assert!(
            seen[1].0.starts_with("/v1/models") && seen[1].1 == format!("Bearer {UNREFERENCED}")
        );

        // --refs-only with no reference refuses before anything launches.
        std::env::remove_var("GITHUB_TOKEN");
        let refused = super::run_async(&command, None, None, true, false, true, |_| {
            panic!("refs-only without a reference reached the registry factory")
        })
        .await;
        assert!(refused
            .unwrap_err()
            .to_string()
            .contains("--refs-only needs at least one NAME=secret://NAME"));
        println!("refs-only verified");
        println!("default verified");
    });
}

/// Child side. Talks to the proxy over raw HTTP/1; never prints responses.
#[test]
fn refs_only_client() {
    if std::env::var(FIXTURE).as_deref() != Ok("1") {
        return;
    }
    let mode = std::fs::read_to_string(MODE_FILE).unwrap();
    let token = std::env::var("PHANTOM_PROXY_TOKEN").unwrap();
    let port: u16 = std::env::var("PHANTOM_PROXY_PORT")
        .unwrap()
        .parse()
        .unwrap();
    assert!(PhantomToken::is_phantom_token(
        &std::env::var("GITHUB_TOKEN").unwrap()
    ));
    let request = |path: &str| {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nx-phantom-proxy-token: {token}\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(!response.contains(REFERENCED) && !response.contains(UNREFERENCED));
        response
    };
    let env_values: Vec<String> = std::env::vars().map(|(_, value)| value).collect();
    assert!(request("/github_api/user").starts_with("HTTP/1.1 200"));
    match mode.as_str() {
        "refs-only" => {
            assert!(
                std::env::var_os("OPENAI_API_KEY").is_none(),
                "unreferenced name reached the child"
            );
            assert!(
                std::env::var_os("OPENAI_BASE_URL").is_none(),
                "unreferenced route override reached the child"
            );
            assert!(
                env_values.iter().all(|value| !value.contains("/openai")),
                "an override for the unreferenced route reached the child"
            );
            assert_eq!(
                std::env::var("PHANTOM_SESSION_KEYS").unwrap(),
                "GITHUB_TOKEN"
            );
            assert!(std::env::var("GITHUB_TOKEN_BASE_URL").is_ok());
            let refused = request("/openai/v1/models");
            assert!(
                !refused.starts_with("HTTP/1.1 2"),
                "unreferenced route was served"
            );
        }
        "default" => {
            assert!(PhantomToken::is_phantom_token(
                &std::env::var("OPENAI_API_KEY").unwrap()
            ));
            assert!(std::env::var("OPENAI_BASE_URL").is_ok());
            assert!(request("/openai/v1/models").starts_with("HTTP/1.1 200"));
        }
        _ => panic!("unknown fixture mode"),
    }
}
