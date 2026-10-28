//! GitHub's built-in route with exec-shaped session placeholders and header
//! authentication. Only this fixture substitutes a loopback upstream; the
//! shipped CLI still requires the exact trusted HTTPS route.
use phantom_core::config::PhantomConfig;
use phantom_core::token::PhantomToken;
use phantom_proxy::test_server::MockServer;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::{BTreeMap, HashMap};

fn registry(upstream: &MockServer) -> ServiceRegistry {
    let canonical = ServiceRegistry::from_config(&BTreeMap::from([(
        "github_api".to_string(),
        PhantomConfig::trusted_builtin_proxy_service("github_api").unwrap(),
    )]));
    let mut route = canonical.match_route("/github_api").unwrap().0.clone();
    assert!(route.target_base == "https://api.github.com");
    assert!(route.header.eq_ignore_ascii_case("authorization"));
    assert!(route.header_format == "Bearer {secret}");
    assert!(route.secret_key == "GITHUB_TOKEN");
    assert!(route.sdk_base_path.is_none());
    route.target_base = format!("http://127.0.0.1:{}", upstream.port);
    let mut registry = ServiceRegistry::new();
    registry.add_route(route);
    registry
}

async fn start(
    upstream: &MockServer,
    placeholder: &str,
    value: Option<&str>,
) -> (ProxyServer, String) {
    let token = ProxyServer::generate_proxy_token();
    let (tokens, values) = match value {
        Some(value) => (
            HashMap::from([(
                placeholder.to_string(),
                ("GITHUB_TOKEN".to_string(), value.to_string()),
            )]),
            HashMap::from([("GITHUB_TOKEN".to_string(), value.to_string())]),
        ),
        None => (HashMap::new(), HashMap::new()),
    };
    let proxy = ProxyServer::start(
        ProxyConfig {
            proxy_token: token.clone(),
            allow_query_token_auth: false,
            ..ProxyConfig::default()
        },
        registry(upstream),
        Interceptor::new_scoped(tokens, values),
    )
    .await
    .unwrap();
    (proxy, token)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

fn root(proxy: &ProxyServer) -> String {
    format!("http://127.0.0.1:{}/github_api", proxy.port())
}

#[tokio::test]
async fn github_api_preserves_graphql_and_pull_operations_with_header_auth() {
    let upstream = MockServer::start().await;
    let placeholder = PhantomToken::generate();
    let fake_key = format!(
        "ghp_FAKE_github_fixture_{}",
        PhantomToken::generate().as_str()
    );
    let (proxy, token) = start(&upstream, placeholder.as_str(), Some(&fake_key)).await;
    let client = client();
    let base = root(&proxy);
    let graphql = serde_json::json!({
        "query": "query($opaque: String!) { viewer { login } }",
        "variables": {"opaque": placeholder.as_str()}
    })
    .to_string();
    let operations = [
        (reqwest::Method::POST, "/graphql", graphql.as_str()),
        (
            reqwest::Method::PUT,
            "/repos/ashlrai/fixture/pulls/42/update-branch",
            r#"{"expected_head_sha":"0123456789abcdef"}"#,
        ),
        (
            reqwest::Method::PUT,
            "/repos/ashlrai/fixture/pulls/42/merge",
            r#"{"merge_method":"squash","sha":"0123456789abcdef"}"#,
        ),
        (
            reqwest::Method::GET,
            "/repos/ashlrai/fixture/pulls?state=open&per_page=100&page=2",
            "",
        ),
    ];
    for (method, path, body) in &operations {
        let response = client
            .request(method.clone(), format!("{base}{path}"))
            .header("x-phantom-proxy-token", &token)
            .header("authorization", format!("token {}", placeholder.as_str()))
            .header("x-opaque", placeholder.as_str())
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .header("user-agent", "phantom-github-fixture")
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "GitHub operation failed");
        assert!(!response.text().await.unwrap().contains(&fake_key));
    }
    let requests = upstream.get_requests();
    assert_eq!(requests.len(), operations.len());
    for (request, (method, path, body)) in requests.iter().zip(&operations) {
        assert!(request.method == method.as_str(), "HTTP method changed");
        assert!(request.path == *path, "GitHub path or query changed");
        assert!(request.body == body.as_bytes(), "request body changed");
        assert!(request.headers["authorization"] == format!("Bearer {fake_key}"));
        assert!(request.headers["x-opaque"] == placeholder.as_str());
        assert!(request.headers["accept"] == "application/vnd.github+json");
        assert!(request.headers["x-github-api-version"] == "2022-11-28");
        assert!(request.headers["user-agent"] == "phantom-github-fixture");
        assert!(!request.headers.contains_key("x-phantom-proxy-token"));
        assert!(!request.path.contains(&token));
        assert!(!request
            .body
            .windows(fake_key.len())
            .any(|part| part == fake_key.as_bytes()));
    }
    proxy.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn github_api_refuses_unauthenticated_and_unavailable_credentials() {
    let upstream = MockServer::start().await;
    let placeholder = PhantomToken::generate();
    let (proxy, token) = start(&upstream, placeholder.as_str(), None).await;
    let client = client();
    let url = format!("{}/graphql", root(&proxy));
    for supplied in [None, Some("invalid-test-session")] {
        let mut request = client.post(&url);
        if let Some(supplied) = supplied {
            request = request.header("x-phantom-proxy-token", supplied);
        }
        assert_eq!(request.send().await.unwrap().status(), 401);
    }
    assert_eq!(
        client
            .post(&url)
            .header("x-phantom-proxy-token", &token)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert!(upstream.get_requests().is_empty());
    proxy.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn github_api_scrubs_hostile_upstream_echoes() {
    let upstream = MockServer::start_echoing("authorization", "application/json").await;
    let placeholder = PhantomToken::generate();
    let fake_key = format!("ghp_FAKE_github_echo_{}", PhantomToken::generate().as_str());
    let (proxy, token) = start(&upstream, placeholder.as_str(), Some(&fake_key)).await;
    let response = client()
        .post(format!("{}/graphql", root(&proxy)))
        .header("x-phantom-proxy-token", &token)
        .body(r#"{"query":"{ viewer { login } }"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    for value in response.headers().values() {
        assert!(!value
            .as_bytes()
            .windows(fake_key.len())
            .any(|part| part == fake_key.as_bytes()));
    }
    assert!(!response.text().await.unwrap().contains(&fake_key));
    let requests = upstream.get_requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers["authorization"] == format!("Bearer {fake_key}"));
    proxy.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn github_api_never_follows_upstream_redirects() {
    let destination = MockServer::start().await;
    let location = format!("http://127.0.0.1:{}/credential-sink", destination.port);
    let upstream = MockServer::start_with_status_and_headers(
        hyper::StatusCode::TEMPORARY_REDIRECT,
        &[("location", location.as_str())],
    )
    .await;
    let placeholder = PhantomToken::generate();
    let fake_key = format!(
        "ghp_FAKE_github_redirect_{}",
        PhantomToken::generate().as_str()
    );
    let (proxy, token) = start(&upstream, placeholder.as_str(), Some(&fake_key)).await;
    let response = client()
        .put(format!(
            "{}/repos/ashlrai/fixture/pulls/42/merge",
            root(&proxy)
        ))
        .header("x-phantom-proxy-token", &token)
        .body(r#"{"merge_method":"squash"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 307);
    assert_eq!(upstream.get_requests().len(), 1);
    assert!(destination.get_requests().is_empty());
    proxy.shutdown().await;
    upstream.shutdown().await;
    destination.shutdown().await;
}
