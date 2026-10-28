//! Protocol fixtures for the supported rows of docs/exec.md. These send real
//! loopback HTTP requests using exec's exported route URLs; they do not invoke
//! or certify installed curl/npm versions. Unsupported CLI launch decisions
//! belong to the CLI's coverage tests, before any proxy request is made.

use phantom_core::config::PhantomConfig;
use phantom_core::token::PhantomToken;
use phantom_proxy::test_server::MockServer;
use phantom_proxy::ServiceRegistry;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

// Deliberately synthetic values; no vault, user config, or network credentials.
const ROUTE_VALUE: &str = "exec-coverage-synthetic-github-vault-value";
const OTHER_VALUE: &str = "exec-coverage-synthetic-unrelated-vault-value";

async fn fixture(
    upstream: &MockServer,
    path_auth: bool,
) -> (ProxyServer, ServiceRegistry, String, String) {
    let services = BTreeMap::from([(
        "github_api".to_string(),
        PhantomConfig::trusted_builtin_proxy_service("github_api").unwrap(),
    )]);
    let mut registry = ServiceRegistry::from_config(&services);
    let mut route = registry.match_route("/github_api/user").unwrap().0.clone();
    // Only the test clone's destination changes. Production route identity,
    // credential ownership, header format, and URL exports are unchanged.
    route.target_base = format!("http://127.0.0.1:{}", upstream.port);
    registry.add_route(route);

    let unrelated_placeholder = PhantomToken::generate().as_str().to_string();
    let interceptor = Interceptor::new_scoped(
        HashMap::from([(
            unrelated_placeholder.clone(),
            ("OTHER_API_KEY".to_string(), OTHER_VALUE.to_string()),
        )]),
        HashMap::from([
            ("GITHUB_TOKEN".to_string(), ROUTE_VALUE.to_string()),
            ("OTHER_API_KEY".to_string(), OTHER_VALUE.to_string()),
        ]),
    );
    let bearer = ProxyServer::generate_proxy_token();
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: bearer.clone(),
            allow_query_token_auth: path_auth,
            ..ProxyConfig::default()
        },
        registry.clone(),
        interceptor,
    )
    .await
    .unwrap();
    (proxy, registry, bearer, unrelated_placeholder)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn exported_url(registry: &ServiceRegistry, port: u16, bearer: Option<&str>) -> String {
    let base = registry
        .base_url_overrides_with_token(port, bearer)
        .into_iter()
        .find(|(name, _)| name == "GITHUB_TOKEN_BASE_URL")
        .unwrap()
        .1;
    format!("{}/user?per_page=1", base.trim_end_matches('/'))
}

#[tokio::test]
async fn curl_and_npm_script_protocol_table_uses_exported_routes_only() {
    // npm's row models an HTTP client inside a script that explicitly reads
    // GITHUB_TOKEN_BASE_URL, not npm registry traffic or automatic URL rewriting.
    for (cli, method) in [
        ("curl", reqwest::Method::GET),
        ("npm script", reqwest::Method::POST),
    ] {
        for path_auth in [false, true] {
            let upstream = MockServer::start().await;
            let (proxy, registry, bearer, placeholder) = fixture(&upstream, path_auth).await;
            let url = exported_url(
                &registry,
                proxy.port(),
                path_auth.then_some(bearer.as_str()),
            );
            let body = format!("{{\"inert\":\"{placeholder}\"}}");
            let mut request = client()
                .request(method.clone(), url)
                // Even a placeholder owned by another secret cannot choose
                // which credential the route injects.
                .header("authorization", format!("Bearer {placeholder}"))
                .header("x-inert-placeholder", &placeholder)
                .body(body.clone());
            if !path_auth {
                request = request.header("x-phantom-proxy-token", &bearer);
            }
            let response = request
                .send()
                .await
                .unwrap_or_else(|_| panic!("{cli}: loopback request failed"));
            assert_eq!(response.status(), reqwest::StatusCode::OK, "{cli}");
            let _ = response
                .bytes()
                .await
                .unwrap_or_else(|_| panic!("{cli}: response read failed"));

            let seen = upstream.get_requests();
            assert_eq!(seen.len(), 1, "{cli}");
            let seen = &seen[0];
            assert_eq!(seen.method, method.as_str(), "{cli}");
            assert!(
                seen.path == "/user?per_page=1",
                "{cli}: wrong upstream path"
            );
            assert!(
                seen.headers["authorization"] == format!("Bearer {ROUTE_VALUE}"),
                "{cli}: wrong route credential"
            );
            assert!(
                seen.headers["x-inert-placeholder"] == placeholder,
                "{cli}: unrelated header was rewritten"
            );
            assert!(
                seen.body == body.as_bytes(),
                "{cli}: request body was rewritten"
            );
            assert!(
                !seen.headers.contains_key("x-phantom-proxy-token"),
                "{cli}: proxy bearer header escaped"
            );
            assert!(
                !seen.path.contains(&bearer),
                "{cli}: proxy bearer path escaped"
            );
            assert!(
                !seen
                    .headers
                    .values()
                    .any(|value| value.contains(&bearer) || value.contains(OTHER_VALUE)),
                "{cli}: unrelated credential escaped"
            );
            proxy.shutdown().await;
            upstream.shutdown().await;
        }
    }
}

#[tokio::test]
async fn explicit_cli_routes_scrub_upstream_auth_echoes() {
    for path_auth in [false, true] {
        let upstream = MockServer::start_echoing("authorization", "application/json").await;
        let (proxy, registry, bearer, _) = fixture(&upstream, path_auth).await;
        let url = exported_url(
            &registry,
            proxy.port(),
            path_auth.then_some(bearer.as_str()),
        );
        let mut request = client().get(url);
        if !path_auth {
            request = request.header("x-phantom-proxy-token", &bearer);
        }
        let response = request
            .send()
            .await
            .unwrap_or_else(|_| panic!("loopback echo request failed"));
        // The echo mock deliberately returns 401 after recording the request.
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(
            response
                .headers()
                .values()
                .all(|value| { !String::from_utf8_lossy(value.as_bytes()).contains(ROUTE_VALUE) }),
            "route credential leaked through response headers"
        );
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| panic!("echo response read failed"));
        assert!(
            !body.contains(ROUTE_VALUE),
            "route credential leaked through response body"
        );
        assert!(body.contains("REDACTED"), "echo must be visibly scrubbed");
        let seen = upstream.get_requests();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].headers["authorization"] == format!("Bearer {ROUTE_VALUE}"));
        proxy.shutdown().await;
        upstream.shutdown().await;
    }
}

#[tokio::test]
async fn explicit_cli_routes_refuse_missing_auth_without_upstream_access() {
    for path_auth in [false, true] {
        let upstream = MockServer::start().await;
        let (proxy, registry, bearer, placeholder) = fixture(&upstream, path_auth).await;
        let url = exported_url(&registry, proxy.port(), None);
        // A provider placeholder authenticates neither the proxy nor its route.
        let response = client()
            .get(&url)
            .header("authorization", format!("Bearer {placeholder}"))
            .send()
            .await
            .unwrap_or_else(|_| panic!("loopback unauthenticated request failed"));
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        let _ = response
            .bytes()
            .await
            .unwrap_or_else(|_| panic!("unauthenticated response read failed"));
        if !path_auth {
            let path_url = exported_url(&registry, proxy.port(), Some(&bearer));
            let response = client()
                .get(path_url)
                .send()
                .await
                .unwrap_or_else(|_| panic!("loopback header-only request failed"));
            assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
            let _ = response
                .bytes()
                .await
                .unwrap_or_else(|_| panic!("header-only response read failed"));
        }
        assert!(
            upstream.get_requests().is_empty(),
            "unauthenticated request reached upstream"
        );
        proxy.shutdown().await;
        upstream.shutdown().await;
    }
}
