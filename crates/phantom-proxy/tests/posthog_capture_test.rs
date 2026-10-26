//! Hermetic capture with exec's registry, session placeholders and proxy auth.
//! Only the library fixture replaces HTTPS with a loopback mock; the shipped
//! CLI has no destination override. No production credentials or network.
use phantom_core::config::PhantomConfig;
use phantom_core::token::PhantomToken;
use phantom_proxy::test_server::MockServer;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn registry(mock: &MockServer) -> ServiceRegistry {
    let services = BTreeMap::from([(
        "posthog_fleet".to_string(),
        PhantomConfig::trusted_builtin_proxy_service("posthog_fleet").unwrap(),
    )]);
    let canonical = ServiceRegistry::from_config(&services);
    let mut route = canonical.match_route("/posthog_fleet").unwrap().0.clone();
    route.target_base = format!("http://127.0.0.1:{}", mock.port);
    let mut registry = ServiceRegistry::new();
    registry.add_route(route);
    registry
}

#[tokio::test]
async fn capture_injects_only_at_allowed_upstream_and_never_discloses_key() {
    let logs = Logs(Arc::new(Mutex::new(Vec::new())));
    let writer = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();
    let mock = MockServer::start().await;
    let fake_key = format!(
        "phc_FAKE_posthog_test_only_{}",
        PhantomToken::generate().as_str()
    );
    let placeholder = PhantomToken::generate();
    let token = ProxyServer::generate_proxy_token();
    let routes = registry(&mock);
    let base = routes.base_url_overrides_with_token(0, Some(&token));
    assert_eq!(base[0].0, "POSTHOG_BASE_URL");
    let proxy = ProxyServer::start(
        ProxyConfig {
            proxy_token: token.clone(),
            allow_query_token_auth: true,
            ..ProxyConfig::default()
        },
        routes,
        Interceptor::new_scoped(
            HashMap::from([(
                placeholder.as_str().to_string(),
                ("POSTHOG_API_KEY".to_string(), fake_key.clone()),
            )]),
            HashMap::from([("POSTHOG_API_KEY".to_string(), fake_key.clone())]),
        ),
    )
    .await
    .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let root = format!("http://127.0.0.1:{}/posthog_fleet", proxy.port());
    let body = format!(
        r#"{{"created_at":"2026-10-26T00:00:00Z","batch":[{{"event":"fleet.work","uuid":"00000000-0000-4000-8000-000000000001","distinct_id":"test-fleet","timestamp":"2026-10-26T00:00:00Z","properties":{{"opaque":"{}"}}}}]}}"#,
        placeholder.as_str()
    );
    for suffix in ["/i/v1/analytics/events", "/i/v1/analytics/events/"] {
        let response = client
            .post(format!("{root}/_phantom/{token}{suffix}"))
            // Neither a client-selected credential nor another header may
            // control the route's secret. Body placeholders stay inert too.
            .header("authorization", format!("Bearer {}", placeholder.as_str()))
            .header("x-unrelated", placeholder.as_str())
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        for value in response.headers().values() {
            assert!(!value
                .as_bytes()
                .windows(fake_key.len())
                .any(|run| run == fake_key.as_bytes()));
        }
        assert!(!response.text().await.unwrap().contains(&fake_key));
    }
    let received = mock.get_requests();
    assert_eq!(received.len(), 2);
    for request in received {
        assert!(request.headers["authorization"] == format!("Bearer {fake_key}"));
        assert!(request.headers["x-unrelated"] == placeholder.as_str());
        assert!(!request.headers.contains_key("x-phantom-proxy-token"));
        assert!(request.body == body.as_bytes());
        assert!(!request.path.contains(&token));
    }
    let before = mock.get_requests().len();
    for path in [
        "/capture/",
        "/batch/",
        "/i/v0/e/",
        "/api/projects/",
        "/i/v1/analytics/events/extra",
        "/i/v1/analytics/events.evil",
    ] {
        let response = client
            .post(format!("{root}{path}"))
            .header("x-phantom-proxy-token", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "path {path}");
    }
    for method in [
        reqwest::Method::GET,
        reqwest::Method::PUT,
        reqwest::Method::DELETE,
        reqwest::Method::HEAD,
    ] {
        let response = client
            .request(method, format!("{root}/i/v1/analytics/events"))
            .header("x-phantom-proxy-token", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    let response = client
        .post(format!("{root}/i/v1/analytics/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(mock.get_requests().len(), before);
    proxy.shutdown().await;

    // Missing route values fail closed even on an allowed endpoint.
    let proxy = ProxyServer::start(
        ProxyConfig {
            proxy_token: token.clone(),
            ..ProxyConfig::default()
        },
        registry(&mock),
        Interceptor::new_scoped(HashMap::new(), HashMap::new()),
    )
    .await
    .unwrap();
    for (path, status) in [("/capture", 403), ("/i/v1/analytics/events", 503)] {
        let response = client
            .post(format!(
                "http://127.0.0.1:{}/posthog_fleet{path}",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
    assert_eq!(mock.get_requests().len(), before);
    proxy.shutdown().await;
    mock.shutdown().await;

    // The hostile-echo fixture intentionally returns 401. Verify that error
    // status and its credential-bearing headers/body are handled separately
    // from the successful capture above; never relax response scrubbing.
    let echo = MockServer::start_echoing("authorization", "application/json").await;
    let proxy = ProxyServer::start(
        ProxyConfig {
            proxy_token: token.clone(),
            ..ProxyConfig::default()
        },
        registry(&echo),
        Interceptor::new_scoped(
            HashMap::from([(
                placeholder.as_str().to_string(),
                ("POSTHOG_API_KEY".to_string(), fake_key.clone()),
            )]),
            HashMap::from([("POSTHOG_API_KEY".to_string(), fake_key.clone())]),
        ),
    )
    .await
    .unwrap();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/posthog_fleet/i/v1/analytics/events",
            proxy.port()
        ))
        .header("x-phantom-proxy-token", &token)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    for value in response.headers().values() {
        assert!(!value
            .as_bytes()
            .windows(fake_key.len())
            .any(|run| run == fake_key.as_bytes()));
    }
    assert!(!response.text().await.unwrap().contains(&fake_key));
    assert!(echo.get_requests()[0].headers["authorization"] == format!("Bearer {fake_key}"));
    proxy.shutdown().await;
    echo.shutdown().await;
    let log_bytes = logs.0.lock().unwrap();
    let log_text = String::from_utf8_lossy(&log_bytes);
    assert!(!log_text.is_empty());
    assert!(!log_text.contains(&fake_key));
    assert!(!log_text.contains(&token));
}
