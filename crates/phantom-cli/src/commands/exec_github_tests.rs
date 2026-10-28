//! Run exec's real vault/session/child/shutdown lifecycle in an isolated copy
//! of the test harness. Only the private registry factory replaces upstream;
//! production configuration validation and child sanitization remain active.
use super::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use wiremock::{Mock, MockServer, ResponseTemplate};

const FIXTURE: &str = "PHANTOM_GITHUB_EXEC_FIXTURE";
const CHILD: &str = "commands::exec::github_tests::github_client";
const RUNNER: &str = "commands::exec::github_tests::exec_fixture";
const VALUE: &str = "github-exec-disposable-value-not-a-provider-credential";
const PATHS: &[(&str, &str, &str)] = &[
    (
        "POST",
        "/graphql",
        r#"{"query":"query { viewer { login } }"}"#,
    ),
    (
        "PUT",
        "/repos/ashlrai/fixture/pulls/42/update-branch",
        r#"{"expected_head_sha":"fixture-sha"}"#,
    ),
    (
        "PUT",
        "/repos/ashlrai/fixture/pulls/42/merge",
        r#"{"merge_method":"squash","sha":"fixture-sha"}"#,
    ),
    (
        "GET",
        "/repos/ashlrai/fixture/pulls?state=open&per_page=100",
        "",
    ),
];

#[test]
fn github_exec_lifecycle_loopback() {
    let root = std::env::temp_dir().canonicalize().unwrap();
    for header_only in ["1", "0"] {
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
                "github-exec-disposable-passphrase",
            )
            .env("PHANTOM_PROXY_HEADER_AUTH_ONLY", header_only)
            .env("GITHUB_TOKEN", VALUE)
            .env("GITHUB_TOKEN_BASE_URL", "https://stale.example.invalid")
            .env("NO_COLOR", "1")
            .env(FIXTURE, "1")
            .current_dir(project.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(45);
        while fixture.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = fixture.kill();
                let _ = fixture.wait();
                panic!("exec fixture exceeded its deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = fixture.wait_with_output().unwrap();
        // Never include captured output in failures: it may contain a
        // credential if a regression defeats the sanitization under test.
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(VALUE), "fixture value escaped into output");
        }
        assert!(
            output.status.success(),
            "exec fixture failed in mode {header_only}"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("github lifecycle verified"));
    }
}

#[test]
fn exec_fixture() {
    if std::env::var(FIXTURE).as_deref() != Ok("1") {
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mock = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(|request: &wiremock::Request| {
                if request.url.path() == "/echo" {
                    ResponseTemplate::new(401)
                        .insert_header("x-echo", VALUE)
                        .set_body_json(serde_json::json!({"error": VALUE}))
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
                }
            })
            .mount(&mock)
            .await;
        let mut config = PhantomConfig::new_with_defaults("github-exec-fixture".to_string());
        config.services.clear();
        config.services.insert(
            "github_api".into(),
            PhantomConfig::trusted_builtin_proxy_service("github_api").unwrap(),
        );
        config.save(Path::new(".phantom.toml")).unwrap();
        // Loading binds the local vault namespace to this canonical project
        // directory, exactly as exec will do when it reads the config.
        let mut config = PhantomConfig::load(Path::new(".phantom.toml")).unwrap();
        let persistent = PhantomToken::generate();
        std::fs::write(".env", format!("GITHUB_TOKEN={}\n", persistent.as_str())).unwrap();
        phantom_vault::try_create_vault(config.local_project_id())
            .unwrap()
            .store("GITHUB_TOKEN", VALUE)
            .unwrap();
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
        let port_file = Path::new("proxy-port");
        super::run_async(&command, None, None, false, |config| {
            let canonical = ServiceRegistry::from_config(&config.services);
            let mut route = canonical.match_route("/github_api").unwrap().0.clone();
            assert!(route.target_base == "https://api.github.com");
            assert!(route.header_format == "Bearer {secret}");
            route.target_base = mock.uri();
            let mut registry = ServiceRegistry::new();
            registry.add_route(route);
            registry
        })
        .await
        .unwrap();

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), PATHS.len() + 1);
        for (request, (method, path, body)) in requests.iter().zip(PATHS) {
            assert!(request.method.as_str() == *method);
            assert!(
                format!(
                    "{}{}",
                    request.url.path(),
                    request
                        .url
                        .query()
                        .map(|q| format!("?{q}"))
                        .unwrap_or_default()
                ) == *path
            );
            assert!(request.body == body.as_bytes());
        }
        for request in &requests {
            assert!(request.headers["authorization"] == format!("Bearer {VALUE}"));
            assert!(!request.headers.contains_key("x-phantom-proxy-token"));
            assert!(!request.url.as_str().contains("_phantom"));
        }
        let port = std::fs::read_to_string(port_file)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_err(),
            "proxy outlived child"
        );
        assert!(std::fs::read_to_string(".env")
            .unwrap()
            .contains(persistent.as_str()));

        // Even the private factory cannot bypass launch validation: an
        // altered destination must fail before the factory or child runs.
        config.services.get_mut("github_api").unwrap().pattern = Some("127.0.0.1".into());
        config.save(Path::new(".phantom.toml")).unwrap();
        let result = super::run_async(&command, None, None, true, |_| {
            panic!("untrusted route reached registry factory")
        })
        .await;
        assert!(result.is_err());
        println!("github lifecycle verified");
    });
}

/// Minimal HTTP/1 client in the exec child; no shell, curl, external network,
/// inherited credentials, or environment dumps. Responses are never printed.
#[test]
fn github_client() {
    if std::env::var(FIXTURE).as_deref() != Ok("1") {
        return;
    }
    let placeholder = std::env::var("GITHUB_TOKEN").unwrap();
    assert!(PhantomToken::is_phantom_token(&placeholder));
    assert!(
        !std::fs::read_to_string(".env")
            .unwrap()
            .contains(&placeholder),
        "persistent mapping was reused as a session credential"
    );
    assert!(std::env::var_os(VAULT_PASSPHRASE_ENV).is_none());
    let token = std::env::var("PHANTOM_PROXY_TOKEN").unwrap();
    let port = std::env::var("PHANTOM_PROXY_PORT")
        .unwrap()
        .parse::<u16>()
        .unwrap();
    std::fs::write("proxy-port", port.to_string()).unwrap();
    let base = std::env::var("GITHUB_TOKEN_BASE_URL").unwrap();
    let origin = format!("http://127.0.0.1:{port}");
    let prefix = base.strip_prefix(&origin).unwrap().trim_end_matches('/');
    let header_only = std::env::var("PHANTOM_PROXY_HEADER_AUTH_ONLY").as_deref() == Ok("1");
    if header_only {
        assert!(prefix == "/github_api");
    } else {
        assert!(prefix == format!("/github_api/_phantom/{token}"));
    }
    let exchange = |method: &str, path: &str, body: &str, auth: Option<&str>| {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let auth = auth
            .map(|t| format!("x-phantom-proxy-token: {t}\r\n"))
            .unwrap_or_default();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n{auth}Authorization: token {placeholder}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(
            !response.contains(VALUE),
            "upstream credential reached child"
        );
        response
    };
    let header_auth = header_only.then_some(token.as_str());
    for (method, path, body) in PATHS {
        let response = exchange(method, &format!("{prefix}{path}"), body, header_auth);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GitHub operation failed"
        );
        assert!(response.contains("\"ok\":true"));
    }
    let response = exchange("GET", &format!("{prefix}/echo"), "", header_auth);
    assert!(response.starts_with("HTTP/1.1 401"));
    // Use the token-free route to exercise missing and bad header auth even
    // in the SDK path-token mode.
    for auth in [None, Some("invalid-test-proxy-bearer")] {
        assert!(exchange("GET", "/github_api/user", "", auth).starts_with("HTTP/1.1 401"));
    }
}
