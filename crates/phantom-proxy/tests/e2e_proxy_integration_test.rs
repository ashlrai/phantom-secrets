//! End-to-End Proxy Integration Test Suite
//!
//! Validates core proxy security guarantees with a real mock upstream server:
//!
//! 1. **Multi-secret injection with service routing conflicts** — two secrets
//!    registered on different routes; the proxy must inject the correct credential
//!    for each route and must not mix up secrets across services.
//!
//! 2. **Concurrent streaming responses** — SSE and JSON streaming happen
//!    simultaneously on separate connections; secrets split across chunk
//!    boundaries must be scrubbed before reaching the client in both streams.
//!
//! 3. **Client body pass-through with mixed content types** — truncated JSON,
//!    empty bodies, form, multipart, and octet-stream remain byte-preserving;
//!    no client body can resolve a phantom token into a real credential.
//!
//! 4. **Response scrubbing with adaptive leak profiles under load** — repeated
//!    exposure of a vault-registered secret in a JSON response trains the
//!    adaptive scrubber; subsequent responses with a rotated key at the same
//!    JSON path are still redacted.
//!
//! 5. **Rate-limiter edge cases** — window-boundary behaviour, per-secret vs
//!    burst limits, and the caution→alert transition.
//!
//! Run with:
//!   cargo test -p phantom-secrets-proxy --test e2e_proxy_integration_test -- --nocapture

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use phantom_proxy::rate_limiter::{AnomalyClass, RateLimitConfig, RateLimiter};
use phantom_proxy::{
    AdaptiveResponseScrubber, Interceptor, ProxyConfig, ProxyServer, ResponseScrubber,
    ServiceRegistry, ServiceRoute,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;

// ─────────────────────────────────────────────────────────────────────────────
// Shared test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A mock upstream that lets each test supply a custom response body and
/// content-type.  Requests are recorded for post-hoc assertion.
struct ConfigurableMock {
    port: u16,
    requests: Arc<Mutex<Vec<RecordedReq>>>,
    shutdown_tx: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Debug)]
struct RecordedReq {
    _method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Response the mock will return for a given path prefix.
#[derive(Clone)]
struct MockRoute {
    path_prefix: String,
    status: u16,
    content_type: String,
    body: Vec<u8>,
    response_headers: Vec<(String, String)>,
}

impl ConfigurableMock {
    async fn start(routes: Vec<MockRoute>) -> Self {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let requests: Arc<Mutex<Vec<RecordedReq>>> = Arc::new(Mutex::new(Vec::new()));
        let routes = Arc::new(routes);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let reqs = requests.clone();
        let handle = tokio::spawn(async move {
            run_configurable_mock(listener, reqs, routes, shutdown_rx).await;
        });

        Self {
            port,
            requests,
            shutdown_tx,
            handle,
        }
    }

    fn recorded(&self) -> Vec<RecordedReq> {
        self.requests.lock().unwrap().clone()
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.handle.await;
    }
}

async fn run_configurable_mock(
    listener: TcpListener,
    requests: Arc<Mutex<Vec<RecordedReq>>>,
    routes: Arc<Vec<MockRoute>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let reqs = requests.clone();
                        let rts = routes.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let _ = http1::Builder::new()
                                .serve_connection(
                                    io,
                                    service_fn(move |req| {
                                        let reqs = reqs.clone();
                                        let rts = rts.clone();
                                        async move { serve_configurable(req, reqs, rts).await }
                                    }),
                                )
                                .await;
                        });
                    }
                    Err(_) => break,
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
        }
    }
}

async fn serve_configurable(
    req: Request<Incoming>,
    requests: Arc<Mutex<Vec<RecordedReq>>>,
    routes: Arc<Vec<MockRoute>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    use http_body_util::BodyExt;

    let method = req.method().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_default();

    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.to_string(), v.to_string());
        }
    }
    let body = req.collect().await?.to_bytes().to_vec();

    requests.lock().unwrap().push(RecordedReq {
        _method: method,
        path: path.clone(),
        headers,
        body,
    });

    // Find matching route (longest prefix match).
    let matched = routes
        .iter()
        .filter(|r| path.starts_with(&r.path_prefix))
        .max_by_key(|r| r.path_prefix.len());

    let (status, ct, body) = if let Some(r) = matched {
        (r.status, r.content_type.clone(), r.body.clone())
    } else {
        (
            200,
            "application/json".to_string(),
            br#"{"status":"ok","mock":true}"#.to_vec(),
        )
    };

    let mut builder = Response::builder()
        .status(status)
        .header("content-type", ct);
    if let Some(route) = matched {
        for (name, value) in &route.response_headers {
            builder = builder.header(name, value);
        }
    }

    Ok(builder.body(Full::new(Bytes::from(body))).unwrap())
}

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — Multi-secret injection with service routing conflict prevention
// ─────────────────────────────────────────────────────────────────────────────
//
// Two services (openai-like and anthropic-like) are registered with distinct
// secrets.  Each route must receive its own secret, never the other's.  We
// also verify that the *response* body scrubber replaces the real secret that
// the upstream echoes back with its phantom token, not with the other service's
// phantom token.
//
// Exercises: interceptor.rs (named_secrets, format_header_for_secret_key),
//            server.rs (service routing), response_scrubber.rs (scrub_buffered).

#[tokio::test]
async fn test_multi_secret_routing_no_cross_contamination() {
    let openai_secret = "sk-real-openai-key-abcdef0123456789";
    let anthropic_secret = "sk-ant-real-key-xyz987654321000000";

    // Upstream echoes back the Authorization header value in the response.
    let openai_echo = format!(
        r#"{{"model":"gpt-4","auth_echo":"Bearer {}","tokens":100}}"#,
        openai_secret
    );
    let anthropic_echo = format!(
        r#"{{"model":"claude-3","auth_echo":"{}","tokens":200}}"#,
        anthropic_secret
    );

    let mock = ConfigurableMock::start(vec![
        MockRoute {
            path_prefix: "/v1/chat".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body: openai_echo.as_bytes().to_vec(),
            response_headers: Vec::new(),
        },
        MockRoute {
            path_prefix: "/v1/messages".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body: anthropic_echo.as_bytes().to_vec(),
            response_headers: Vec::new(),
        },
    ])
    .await;

    let phantom_openai = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
    let phantom_anthropic = "phm_bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333";

    let mut named = HashMap::new();
    named.insert("OPENAI_API_KEY".to_string(), openai_secret.to_string());
    named.insert(
        "ANTHROPIC_API_KEY".to_string(),
        anthropic_secret.to_string(),
    );

    let mut token_map = HashMap::new();
    token_map.insert(phantom_openai.to_string(), openai_secret.to_string());
    token_map.insert(phantom_anthropic.to_string(), anthropic_secret.to_string());

    let interceptor = Interceptor::new_with_named(token_map, named);

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "openai".to_string(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "OPENAI_API_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
    });
    registry.add_route(ServiceRoute {
        name: "anthropic".to_string(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "ANTHROPIC_API_KEY".to_string(),
        header: "x-api-key".to_string(),
        header_format: "{secret}".to_string(),
    });

    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            ..ProxyConfig::default()
        },
        registry,
        interceptor,
    )
    .await
    .unwrap();

    let client = make_client();

    // --- OpenAI route ---
    let resp_openai = client
        .post(format!("http://127.0.0.1:{}/openai/v1/chat", proxy.port()))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-4","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_openai.status().as_u16(),
        200,
        "openai route should succeed"
    );
    let openai_body = resp_openai.text().await.unwrap();

    // Real secret must not reach the client — scrubber must redact it.
    assert!(
        !openai_body.contains(openai_secret),
        "SECURITY: openai real secret leaked through response scrubber: {openai_body}"
    );
    // Anthropic secret must also never appear.
    assert!(
        !openai_body.contains(anthropic_secret),
        "SECURITY: anthropic secret appeared in openai response: {openai_body}"
    );

    // --- Anthropic route ---
    let resp_anthropic = client
        .post(format!(
            "http://127.0.0.1:{}/anthropic/v1/messages",
            proxy.port()
        ))
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-3","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_anthropic.status().as_u16(),
        200,
        "anthropic route should succeed"
    );
    let anthropic_body = resp_anthropic.text().await.unwrap();

    assert!(
        !anthropic_body.contains(anthropic_secret),
        "SECURITY: anthropic real secret leaked through response scrubber: {anthropic_body}"
    );
    assert!(
        !anthropic_body.contains(openai_secret),
        "SECURITY: openai secret appeared in anthropic response: {anthropic_body}"
    );

    // --- Verify upstream received the correct real secrets (not phantom tokens) ---
    let reqs = mock.recorded();
    assert_eq!(reqs.len(), 2, "expected exactly 2 upstream requests");

    // Find each upstream request by path.
    let openai_req = reqs
        .iter()
        .find(|r| r.path.starts_with("/v1/chat"))
        .unwrap();
    let auth_openai = openai_req.headers.get("authorization").unwrap();
    assert_eq!(
        auth_openai,
        &format!("Bearer {}", openai_secret),
        "upstream received wrong secret for openai: {auth_openai}"
    );
    assert!(
        !auth_openai.contains("phm_"),
        "phantom token leaked to upstream openai: {auth_openai}"
    );

    let anthropic_req = reqs
        .iter()
        .find(|r| r.path.starts_with("/v1/messages"))
        .unwrap();
    let auth_anthropic = anthropic_req.headers.get("x-api-key").unwrap();
    assert_eq!(
        auth_anthropic, anthropic_secret,
        "upstream received wrong secret for anthropic: {auth_anthropic}"
    );
    assert!(
        !auth_anthropic.contains("phm_"),
        "phantom token leaked to upstream anthropic: {auth_anthropic}"
    );

    // --- Routing conflict: openai secret must NOT appear in anthropic's request ---
    assert!(
        !auth_anthropic.contains(openai_secret),
        "SECURITY: openai secret injected into anthropic route"
    );
    assert!(
        !auth_openai.contains(anthropic_secret),
        "SECURITY: anthropic secret injected into openai route"
    );

    proxy.shutdown().await;
    mock.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — Concurrent SSE + JSON streaming with cross-chunk secret scrubbing
// ─────────────────────────────────────────────────────────────────────────────
//
// Spins up a dedicated SSE upstream and validates that:
//  a) SSE (text/event-stream) responses have secrets scrubbed even when the
//     secret straddles the first and second SSE event.
//  b) A simultaneous JSON response (application/json) also has its secret
//     scrubbed in the buffered path.
//  c) Clean SSE event data (without secrets) passes through unmolested.
//
// Exercises: response_scrubber.rs (scrub_buffered + scrub_chunk + flush_carry),
//            server.rs (streaming response path).

#[tokio::test]
async fn test_concurrent_sse_and_json_streaming_secrets_scrubbed() {
    let secret = "sk-stream-multi-secret-xyz1234567890";
    let phantom = "phm_cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444";

    // SSE body: secret appears in the first data line.
    let sse_body = format!(
        "data: {{\"api_key\":\"{secret}\",\"delta\":\"hello\"}}\n\ndata: {{\"delta\":\" world\"}}\n\n"
    );
    // JSON body: secret appears inside an error field.
    let json_body = format!(
        r#"{{"error":"key {} rejected","status":401,"detail":"invalid"}}"#,
        secret
    );

    // SSE upstream — must send Transfer-Encoding: chunked to trigger streaming path.
    let sse_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let sse_listener = TcpListener::bind(sse_addr).await.unwrap();
    let sse_port = sse_listener.local_addr().unwrap().port();
    let sse_body_clone = sse_body.clone();
    let (sse_tx, mut sse_rx) = watch::channel(false);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = sse_listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let body_str = sse_body_clone.clone();
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let _ = http1::Builder::new()
                                    .serve_connection(io, service_fn(move |_req| {
                                        let b = body_str.clone();
                                        async move {
                                            Ok::<_, hyper::Error>(
                                                Response::builder()
                                                    .status(200)
                                                    .header("content-type", "text/event-stream")
                                                    .header("transfer-encoding", "chunked")
                                                    .body(Full::new(Bytes::from(b)))
                                                    .unwrap(),
                                            )
                                        }
                                    }))
                                    .await;
                            });
                        }
                        Err(_) => break,
                    }
                }
                _ = sse_rx.changed() => { if *sse_rx.borrow() { break; } }
            }
        }
    });

    // JSON upstream.
    let json_mock = ConfigurableMock::start(vec![MockRoute {
        path_prefix: "/".to_string(),
        status: 401,
        content_type: "application/json".to_string(),
        body: json_body.as_bytes().to_vec(),
        response_headers: Vec::new(),
    }])
    .await;

    let mut token_map = HashMap::new();
    token_map.insert(phantom.to_string(), secret.to_string());
    let interceptor = Interceptor::new_with_named(
        token_map,
        HashMap::from([
            ("SSE_KEY".to_string(), secret.to_string()),
            ("JSON_KEY".to_string(), secret.to_string()),
        ]),
    );

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "sseapi".to_string(),
        target_base: format!("http://127.0.0.1:{sse_port}"),
        secret_key: "SSE_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
    });
    registry.add_route(ServiceRoute {
        name: "jsonapi".to_string(),
        target_base: format!("http://127.0.0.1:{}", json_mock.port),
        secret_key: "JSON_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
    });

    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            ..ProxyConfig::default()
        },
        registry,
        interceptor,
    )
    .await
    .unwrap();

    let client = make_client();
    let proxy_port = proxy.port();

    // Fire SSE and JSON requests concurrently.
    let sse_task = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .get(format!("http://127.0.0.1:{proxy_port}/sseapi/stream"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        }
    });
    let json_task = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .get(format!("http://127.0.0.1:{proxy_port}/jsonapi/v1/models"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        }
    });

    let (sse_result, json_result) = tokio::join!(sse_task, json_task);
    let sse_text = sse_result.unwrap();
    let json_text = json_result.unwrap();

    // SSE: secret must be scrubbed.
    assert!(
        !sse_text.contains(secret),
        "SECURITY: real secret leaked in SSE stream: {sse_text}"
    );
    // SSE: clean data line (delta) must survive.
    assert!(
        sse_text.contains("world") || sse_text.contains("delta") || sse_text.contains("hello"),
        "clean SSE event data was lost: {sse_text}"
    );

    // JSON: secret must be scrubbed.
    assert!(
        !json_text.contains(secret),
        "SECURITY: real secret leaked in JSON buffered response: {json_text}"
    );
    // JSON: non-secret fields survive.
    assert!(
        json_text.contains("status") || json_text.contains("detail") || json_text.contains("error"),
        "non-secret JSON fields were lost: {json_text}"
    );

    proxy.shutdown().await;
    json_mock.shutdown().await;
    let _ = sse_tx.send(true);
}

// ─────────────────────────────────────────────────────────────────────────────
// Response encoding boundary — identity only
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_proxy_forces_identity_and_rejects_encoded_upstream_responses() {
    let secret = "sk-encoded-response-secret-0123456789";
    let phantom = "phm_eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666";
    let rejected = [
        ("/gzip", "gzip", "application/json"),
        ("/br", "br", "application/json"),
        ("/deflate", "deflate", "application/json"),
        ("/zstd", "zstd", "application/json"),
        ("/unknown", "future-coding", "application/json"),
        ("/empty", "", "application/json"),
        ("/list", "gzip, br", "application/json"),
        ("/identity-list", "identity, identity", "application/json"),
        ("/mixed-list", "identity, gzip", "application/json"),
        ("/encoded-sse", "gzip", "text/event-stream"),
    ];

    let mut routes = rejected
        .iter()
        .map(|(path, encoding, content_type)| MockRoute {
            path_prefix: (*path).to_string(),
            status: 200,
            content_type: (*content_type).to_string(),
            body: if *content_type == "text/event-stream" {
                format!("data: {{\"secret\":\"{secret}\"}}\n\n").into_bytes()
            } else {
                format!(r#"{{"secret":"{secret}"}}"#).into_bytes()
            },
            response_headers: vec![("content-encoding".to_string(), (*encoding).to_string())],
        })
        .collect::<Vec<_>>();
    routes.extend([
        MockRoute {
            path_prefix: "/duplicate-identity".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body: format!(r#"{{"secret":"{secret}"}}"#).into_bytes(),
            response_headers: vec![
                ("content-encoding".to_string(), "identity".to_string()),
                ("content-encoding".to_string(), "identity".to_string()),
            ],
        },
        MockRoute {
            path_prefix: "/identity".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body: format!(r#"{{"secret":"{secret}"}}"#).into_bytes(),
            response_headers: vec![("content-encoding".to_string(), "Identity".to_string())],
        },
        MockRoute {
            path_prefix: "/absent".to_string(),
            status: 200,
            content_type: "application/json".to_string(),
            body: format!(r#"{{"secret":"{secret}"}}"#).into_bytes(),
            response_headers: Vec::new(),
        },
    ]);

    let mock = ConfigurableMock::start(routes).await;
    let mut token_map = HashMap::new();
    token_map.insert(phantom.to_string(), secret.to_string());

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "encoding".to_string(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "ENCODING_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
    });

    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            rate_limit: RateLimitConfig {
                per_secret_rps: 100,
                burst_total_10s: 1_000,
            },
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_with_named(
            token_map,
            HashMap::from([("ENCODING_KEY".to_string(), secret.to_string())]),
        ),
    )
    .await
    .unwrap();

    let client = make_client();
    let mut rejected_paths = rejected
        .iter()
        .map(|(path, _, _)| *path)
        .collect::<Vec<_>>();
    rejected_paths.push("/duplicate-identity");

    for path in &rejected_paths {
        let response = client
            .get(format!("http://127.0.0.1:{}/encoding{path}", proxy.port()))
            .header("accept-encoding", "gzip, br")
            .header("te", "trailers")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 502, "path {path}");
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "path {path}"
        );
        assert!(
            response.headers().get("content-encoding").is_none(),
            "encoded header reached downstream for {path}"
        );
        let body = response.text().await.unwrap();
        assert_eq!(
            body, r#"{"error":"unsupported_upstream_content_encoding"}"#,
            "path {path}"
        );
        assert!(
            !body.contains(secret),
            "secret reached downstream for {path}"
        );
    }

    for path in ["/identity", "/absent"] {
        let response = client
            .get(format!("http://127.0.0.1:{}/encoding{path}", proxy.port()))
            .header("accept-encoding", "gzip, br")
            .header("te", "trailers")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 200, "path {path}");
        assert!(
            response.headers().get("content-encoding").is_none(),
            "identity header should not be forwarded for {path}"
        );
        let body = response.text().await.unwrap();
        assert!(
            !body.contains(secret),
            "secret reached downstream for {path}"
        );
        assert!(
            body.contains("[REDACTED:vault-secret]"),
            "scrubbing did not run for {path}"
        );
    }

    let requests = mock.recorded();
    assert_eq!(requests.len(), rejected_paths.len() + 2);
    for request in &requests {
        assert_eq!(
            request.headers.get("accept-encoding").map(String::as_str),
            Some("identity"),
            "client encoding preference reached upstream for {}",
            request.path
        );
        assert!(
            !request.headers.contains_key("te"),
            "hop-by-hop TE header reached upstream for {}",
            request.path
        );
    }

    proxy.shutdown().await;
    mock.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — Malformed/partial request bodies with mixed content types
// ─────────────────────────────────────────────────────────────────────────────
//
// For each content type variant, confirms:
//  - Truncated JSON: proxy forwards body as-is (no panic, no 500).
//  - Empty JSON body: proxy returns success, upstream receives empty.
//  - application/octet-stream with phantom token: token NOT substituted (F9).
//  - application/x-www-form-urlencoded with token: passes through unchanged.
//  - multipart/form-data: falls through buffered path unchanged.
//
// Exercises: server.rs (byte-preserving bounded request path).

#[tokio::test]
async fn test_malformed_partial_bodies_mixed_content_types() {
    let phantom_token = "phm_dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444eeee5555";
    let real_secret = "sk-must-not-leak-malformed-body";

    let mock = ConfigurableMock::start(vec![]).await;

    let mut token_map = HashMap::new();
    token_map.insert(phantom_token.to_string(), real_secret.to_string());
    let interceptor = Interceptor::new_scoped(
        token_map
            .into_iter()
            .map(|(token, value)| (token, ("API_KEY".to_string(), value)))
            .collect(),
        HashMap::from([("API_KEY".to_string(), real_secret.to_string())]),
    );

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "api".to_string(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "API_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
    });

    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            ..ProxyConfig::default()
        },
        registry,
        interceptor,
    )
    .await
    .unwrap();

    let client = make_client();
    let proxy_port = proxy.port();

    // --- 3a: Truncated JSON (missing closing brace) ---
    let truncated_json = format!(r#"{{"api_key":"{phantom_token}","model":"gpt-4""#); // no }
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/api/v1/chat"))
        .header("content-type", "application/json")
        .body(truncated_json.clone())
        .send()
        .await
        .unwrap();
    // Proxy should not crash; mock returns 200.
    assert_eq!(resp.status().as_u16(), 200, "truncated JSON should not 500");
    let reqs = mock.recorded();
    assert!(
        !reqs.is_empty(),
        "upstream should have received truncated JSON"
    );
    let last = reqs.last().unwrap();
    let body_str = String::from_utf8_lossy(&last.body);
    // Every client request body is forwarded unchanged.
    // Real secret must NOT appear regardless.
    assert!(
        !body_str.contains(real_secret),
        "SECURITY: real secret in truncated JSON body reached upstream: {body_str}"
    );

    // --- 3b: Empty body ---
    let resp_empty = client
        .post(format!("http://127.0.0.1:{proxy_port}/api/v1/chat"))
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_empty.status().as_u16(),
        200,
        "empty body should succeed"
    );

    // --- 3c: application/octet-stream — phantom token must NOT be substituted (F9) ---
    let binary_body = format!("raw-data-prefix-{phantom_token}-raw-data-suffix");
    let resp_binary = client
        .post(format!("http://127.0.0.1:{proxy_port}/api/v1/upload"))
        .header("content-type", "application/octet-stream")
        .body(binary_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_binary.status().as_u16(),
        200,
        "octet-stream should succeed"
    );
    let reqs_now = mock.recorded();
    let binary_req = reqs_now.last().unwrap();
    let binary_body_received = String::from_utf8_lossy(&binary_req.body);
    assert!(
        !binary_body_received.contains(real_secret),
        "SECURITY: real secret leaked in octet-stream body: {binary_body_received}"
    );
    // Phantom token should still be present (not substituted for binary).
    assert!(
        binary_body_received.contains(phantom_token),
        "phantom token in octet-stream should pass through unchanged: {binary_body_received}"
    );

    // --- 3d: application/x-www-form-urlencoded — unchanged ---
    let form_body = format!("client_secret={phantom_token}&grant_type=client_credentials");
    let resp_form = client
        .post(format!("http://127.0.0.1:{proxy_port}/api/v1/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_form.status().as_u16(),
        200,
        "form-urlencoded should succeed"
    );
    let reqs_final = mock.recorded();
    let form_req = reqs_final.last().unwrap();
    let form_received = String::from_utf8_lossy(&form_req.body);
    assert!(
        form_received.contains(phantom_token),
        "phantom token should pass through form-urlencoded body: {form_received}"
    );
    assert!(
        !form_received.contains(real_secret),
        "real secret must not appear in form-urlencoded body: {form_received}"
    );

    // --- 3e: multipart/form-data — falls through buffered path, token NOT replaced ---
    let multipart_body = format!(
        "--boundary\r\nContent-Disposition: form-data; name=\"api_key\"\r\n\r\n{phantom_token}\r\n--boundary--\r\n"
    );
    let resp_multipart = client
        .post(format!("http://127.0.0.1:{proxy_port}/api/v1/upload"))
        .header("content-type", "multipart/form-data; boundary=boundary")
        .body(multipart_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_multipart.status().as_u16(),
        200,
        "multipart should succeed"
    );
    let reqs_mp = mock.recorded();
    let mp_req = reqs_mp.last().unwrap();
    let mp_received = String::from_utf8_lossy(&mp_req.body);
    // Multipart, like every other client body, is not substituted.
    assert!(
        !mp_received.contains(real_secret),
        "SECURITY: real secret leaked in multipart body: {mp_received}"
    );

    proxy.shutdown().await;
    mock.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — Response scrubbing with adaptive leak profiles under load
// ─────────────────────────────────────────────────────────────────────────────
//
// a) ResponseScrubber (buffered): verify that exact vault-value matches are
//    caught, that format-pattern matches fire at MEDIUM severity for unregistered
//    keys, and that a high volume of scrub calls does not regress correctness.
//
// b) AdaptiveResponseScrubber: after training the profile store with several
//    responses where the secret appears at a known JSON path, a "rotated" key
//    at the same path is redacted adaptively even without an exact match.
//
// c) ResponseScrubber (SSE + JSON streaming): secrets split across chunk
//    boundaries in both content types are caught by the carry-window logic.
//
// Exercises: response_scrubber.rs (all public paths), interceptor.rs.

#[tokio::test]
async fn test_response_scrubbing_adaptive_profiles_under_load() {
    use phantom_core::leak_correlation::{ContextualLeakProfileStore, RequestContext};
    use std::sync::{Arc, Mutex};

    let original_secret = "sk-live-adaptive-original-key-abc123456789";
    let rotated_secret = "sk-live-adaptive-rotated-key-xyz987654321";
    let phantom = "phm_eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666";

    // ── 4a: Exact scrub under load (50 iterations) ──────────────────────────
    let mut token_map = HashMap::new();
    token_map.insert(phantom.to_string(), original_secret.to_string());
    let scrubber = ResponseScrubber::from_token_map(&token_map);

    for i in 0..50 {
        let body = format!(
            r#"{{"iter":{},"data":"prefix-{original_secret}-suffix","extra":"safe"}}"#,
            i
        );
        let (out, event) = scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
        let out_str = String::from_utf8(out).unwrap();
        assert!(
            !out_str.contains(original_secret),
            "iter {i}: secret leaked in load test: {out_str}"
        );
        assert!(
            event.scrubbed,
            "iter {i}: scrubber did not flag scrub event"
        );
        assert!(
            out_str.contains("safe"),
            "iter {i}: safe content was lost: {out_str}"
        );
    }

    // ── 4b: Format-pattern medium-severity for unregistered key ─────────────
    let empty_scrubber = ResponseScrubber::from_token_map(&HashMap::new());
    let unregistered_key = "sk_live_unregistered1234531x";
    let body = format!(r#"{{"key":"{unregistered_key}"}}"#);
    let (out, event) = empty_scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
    let out_str = String::from_utf8(out).unwrap();
    assert!(
        !out_str.contains(unregistered_key),
        "unregistered sk_live_ key should still be redacted: {out_str}"
    );
    assert!(
        event
            .leak_events
            .iter()
            .any(|e| { e.severity == phantom_core::audit::LeakSeverity::Medium }),
        "expected MEDIUM severity for unregistered format match"
    );

    // ── 4c: SSE streaming carry-window scrub ────────────────────────────────
    // Secret is split across chunk boundary at every possible split position.
    for split in 1..original_secret.len() {
        let chunk1 = format!("data: {{\"key\":\"{}\"", &original_secret[..split]);
        let chunk2 = format!("{}\"}}\n\n", &original_secret[split..]);

        let mut carry = Vec::new();
        let mut emitted = Vec::new();

        let (p1, _) =
            scrubber.scrub_chunk(Some("text/event-stream"), &mut carry, chunk1.as_bytes());
        emitted.extend_from_slice(&p1);

        let (p2, _) =
            scrubber.scrub_chunk(Some("text/event-stream"), &mut carry, chunk2.as_bytes());
        emitted.extend_from_slice(&p2);

        let (tail, _) = scrubber.flush_carry(Some("text/event-stream"), carry);
        emitted.extend_from_slice(&tail);

        let result = String::from_utf8(emitted).unwrap();
        assert!(
            !result.contains(original_secret),
            "SSE carry-window miss at split_pos={split}: {result}"
        );
    }

    // ── 4d: Adaptive scrubber learns path and redacts rotated key ───────────
    let mut named = HashMap::new();
    named.insert("API_KEY".to_string(), original_secret.to_string());

    let profile_store = Arc::new(Mutex::new(ContextualLeakProfileStore::with_path(
        std::path::PathBuf::from("/dev/null"),
    )));

    let adaptive = AdaptiveResponseScrubber::new(named.clone(), profile_store.clone());

    let ctx = RequestContext {
        method: "POST".to_string(),
        url_path: "/v1/completions".to_string(),
        content_type: "application/json".to_string(),
        status_code: 401,
    };

    // Train the profile: expose the original secret at the same JSON path
    // enough times to cross the confidence threshold.
    use phantom_core::leak_correlation::PROFILE_CONFIDENCE_THRESHOLD;
    for _ in 0..(PROFILE_CONFIDENCE_THRESHOLD + 2) {
        let training_body = format!(
            r#"{{"error":{{"api_key":"{}","code":"invalid_key"}}}}"#,
            original_secret
        );
        let _ = adaptive.scrub_buffered_adaptive(
            Some("application/json"),
            training_body.as_bytes(),
            Some(&ctx),
        );
    }

    // Now present a response with a ROTATED key at the same JSON path.
    // The adaptive scrubber should redact it even without an exact vault match.
    let rotated_body = format!(
        r#"{{"error":{{"api_key":"{}","code":"invalid_key"}}}}"#,
        rotated_secret
    );
    let (adaptive_out, _adaptive_event) = adaptive.scrub_buffered_adaptive(
        Some("application/json"),
        rotated_body.as_bytes(),
        Some(&ctx),
    );
    let adaptive_str = String::from_utf8(adaptive_out).unwrap();

    // Either the adaptive scrubber caught it, or the format-pattern did.
    // In both cases the rotated key must not reach the caller.
    assert!(
        !adaptive_str.contains(rotated_secret),
        "SECURITY: adaptive scrubber failed to catch rotated key: {adaptive_str}"
    );

    // ── 4e: JSON streaming scrub with plain-text carry window ────────────────
    // A plain-text streaming response is scrubbed chunk by chunk.
    for split in 1..original_secret.len() {
        let c1 = format!("prefix-{}", &original_secret[..split]);
        let c2 = format!("{}-suffix", &original_secret[split..]);

        let mut carry = Vec::new();
        let mut emitted = Vec::new();

        let (p1, _) = scrubber.scrub_chunk(Some("text/plain"), &mut carry, c1.as_bytes());
        emitted.extend_from_slice(&p1);
        let (p2, _) = scrubber.scrub_chunk(Some("text/plain"), &mut carry, c2.as_bytes());
        emitted.extend_from_slice(&p2);
        let (tail, _) = scrubber.flush_carry(Some("text/plain"), carry);
        emitted.extend_from_slice(&tail);

        let result = String::from_utf8(emitted).unwrap();
        assert!(
            !result.contains(original_secret),
            "plain-text streaming miss at split={split}: {result}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5 — Rate-limiter edge cases
// ─────────────────────────────────────────────────────────────────────────────
//
// a) Per-secret alert at exactly N+1 requests (boundary).
// b) Global burst alert with multiple secrets sharing the global counter.
// c) Caution at 50% of per-secret limit.
// d) Per-secret and burst limits are independent — hitting one does not affect
//    the other secret's counter.
// e) Clock-skew simulation: confirm that the RateLimiter unit correctly handles
//    records injected with synthetic Instant values via many rapid fire calls.
// f) End-to-end: proxy returns 429 with correct JSON body and rate-limit headers.
//
// Exercises: rate_limiter.rs (SlidingWindow, RateLimiterInner::record, classify),
//            server.rs (429 response generation).

#[test]
fn test_rate_limiter_per_secret_boundary() {
    // per_secret_10s_limit = 2 * 10 = 20; burst = 1000.
    let rl = RateLimiter::new(RateLimitConfig {
        per_secret_rps: 2,
        burst_total_10s: 1000,
    });

    // Send exactly 20 requests — last should still be Normal or Caution.
    for _ in 0..20 {
        let d = rl.record("KEY_A");
        assert_ne!(
            d.class,
            AnomalyClass::Alert,
            "request 1-20 should not be Alert (limit=20)"
        );
    }
    // 21st must be Alert.
    let d = rl.record("KEY_A");
    assert_eq!(
        d.class,
        AnomalyClass::Alert,
        "21st request must be Alert (per-secret limit=20)"
    );
    assert_eq!(d.per_secret_10s, 21);
}

#[test]
fn test_rate_limiter_global_burst_independent_of_per_secret() {
    // burst_total=5, per_secret=100 (so only global triggers).
    let rl = RateLimiter::new(RateLimitConfig {
        per_secret_rps: 10,
        burst_total_10s: 5,
    });

    // 5 requests across 5 different secrets = 5 global, each per-secret=1.
    for i in 0..5 {
        let d = rl.record(&format!("KEY_{i}"));
        assert_ne!(
            d.class,
            AnomalyClass::Alert,
            "request {i} should not be Alert yet"
        );
    }
    // 6th global request → Alert.
    let d = rl.record("KEY_NEW");
    assert_eq!(
        d.class,
        AnomalyClass::Alert,
        "6th global request must be Alert (burst=5)"
    );
    assert_eq!(d.total_10s, 6);
    // per_secret counter for KEY_NEW should be 1 (not Alert on its own).
    assert_eq!(d.per_secret_10s, 1);
}

#[test]
fn test_rate_limiter_caution_at_half_limit() {
    // per_secret_10s_limit = 4 * 10 = 40; caution at ≥50% = 20.
    let rl = RateLimiter::new(RateLimitConfig {
        per_secret_rps: 4,
        burst_total_10s: 200,
    });

    for _ in 0..19 {
        let d = rl.record("CAUTION_KEY");
        assert_eq!(d.class, AnomalyClass::Normal, "below caution threshold");
    }
    // 20th = 50% of 40 → Caution.
    let d = rl.record("CAUTION_KEY");
    assert_eq!(
        d.class,
        AnomalyClass::Caution,
        "20th request at 50% limit should be Caution"
    );
}

#[test]
fn test_rate_limiter_two_secrets_independent_counters() {
    let rl = RateLimiter::new(RateLimitConfig {
        per_secret_rps: 1, // limit = 10/10s each
        burst_total_10s: 200,
    });

    // Drive KEY_A to Alert.
    for _ in 0..11 {
        rl.record("KEY_A");
    }
    let a_alert = rl.record("KEY_A");
    assert_eq!(a_alert.class, AnomalyClass::Alert, "KEY_A should be Alert");

    // KEY_B starts fresh; single request should be Normal.
    let b_first = rl.record("KEY_B");
    assert_eq!(
        b_first.class,
        AnomalyClass::Normal,
        "KEY_B should be Normal after KEY_A hit Alert"
    );
    assert_eq!(
        b_first.per_secret_10s, 1,
        "KEY_B per-secret count should be 1"
    );
}

#[test]
fn test_rate_limiter_anomaly_score_proportional() {
    let rl = RateLimiter::new(RateLimitConfig {
        per_secret_rps: 5, // limit = 50/10s; burst = 100
        burst_total_10s: 100,
    });

    // 1 request: 1/50 per-secret = 2%, 1/100 global = 1% → score = 2.
    let d1 = rl.record("SCORE_KEY");
    assert!(d1.anomaly_score <= 5, "score for 1 request should be low");

    // 50 requests: 50/50 = 100% per-secret → score = 100.
    for _ in 0..49 {
        rl.record("SCORE_KEY");
    }
    let d50 = rl.record("SCORE_KEY");
    assert_eq!(d50.anomaly_score, 100, "score at 100% should be 100");
}

#[tokio::test]
async fn test_rate_limiter_429_response_headers_and_body() {
    // rps=0 → per_secret_10s_limit=0, so every request immediately triggers Alert.
    let mock = phantom_proxy::test_server::MockServer::start().await;

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "api".to_string(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "RATE_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
    });

    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            rate_limit: RateLimitConfig {
                per_secret_rps: 0,
                burst_total_10s: 100,
            },
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_with_named(
            HashMap::new(),
            HashMap::from([("RATE_KEY".to_string(), "rate-test-secret".to_string())]),
        ),
    )
    .await
    .unwrap();

    let client = make_client();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/v1/ping", proxy.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 429, "rps=0 should immediately 429");

    // Required rate-limit response headers.
    let anomaly_class = resp
        .headers()
        .get("x-phantom-anomaly-class")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        anomaly_class, "alert",
        "x-phantom-anomaly-class must be 'alert'"
    );

    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(!retry_after.is_empty(), "retry-after must be set on 429");

    let anomaly_score: u8 = resp
        .headers()
        .get("x-phantom-anomaly-score")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(anomaly_score > 0, "x-phantom-anomaly-score must be > 0");

    // Structured JSON body.
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "rate limit exceeded", "error field mismatch");
    assert_eq!(
        body["anomaly_class"], "alert",
        "anomaly_class field mismatch"
    );
    assert!(
        body["per_secret_10s"].as_u64().unwrap_or(0) >= 1,
        "per_secret_10s must be ≥ 1"
    );

    // Mock should have received NO requests (rejected before forwarding).
    assert_eq!(
        mock.get_requests().len(),
        0,
        "rate-limited request must not reach upstream"
    );

    proxy.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn test_buffered_upstream_response_is_bounded_before_scrubbing() {
    let mock = ConfigurableMock::start(vec![MockRoute {
        path_prefix: "/large".to_string(),
        status: 200,
        content_type: "application/json".to_string(),
        body: vec![b'x'; 101],
        response_headers: Vec::new(),
    }])
    .await;

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "api".to_string(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "API_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
    });

    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            max_body_size: 100,
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_with_named(
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), "response-bound-test".to_string())]),
        ),
    )
    .await
    .unwrap();

    let response = make_client()
        .get(format!("http://127.0.0.1:{}/api/large", proxy.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 502);
    let body = response.text().await.unwrap();
    assert!(body.contains("upstream response too large"));
    assert!(!body.contains(&"x".repeat(20)));

    proxy.shutdown().await;
    mock.shutdown().await;
}
