use crate::interceptor::Interceptor;
use crate::services::ServiceRegistry;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

/// Configuration for the proxy server.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Port to listen on (0 = ephemeral)
    pub port: u16,
    /// Session token for proxy authentication (defense-in-depth)
    pub proxy_token: String,
    /// Maximum request body size in bytes (default: 10MB)
    pub max_body_size: usize,
    /// Upstream request timeout in seconds (default: 30)
    pub upstream_timeout_secs: u64,
    /// Connection timeout in seconds (default: 5)
    pub connect_timeout_secs: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 0,
            proxy_token: String::new(),
            max_body_size: 10 * 1024 * 1024, // 10MB
            upstream_timeout_secs: 30,
            connect_timeout_secs: 5,
        }
    }
}

/// The running proxy server handle.
pub struct ProxyServer {
    /// The actual port the server bound to
    pub port: u16,
    /// Shutdown signal sender
    shutdown_tx: watch::Sender<bool>,
    /// Server task handle
    handle: tokio::task::JoinHandle<()>,
}

impl ProxyServer {
    /// Start the proxy server.
    pub async fn start(
        config: ProxyConfig,
        registry: ServiceRegistry,
        interceptor: Interceptor,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
        let listener = TcpListener::bind(addr).await?;
        let actual_port = listener.local_addr()?.port();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let state = Arc::new(ProxyState {
            registry,
            interceptor,
            proxy_token: config.proxy_token,
            max_body_size: config.max_body_size,
            http_client: reqwest::Client::builder()
                .danger_accept_invalid_certs(false)
                .timeout(std::time::Duration::from_secs(config.upstream_timeout_secs))
                .connect_timeout(std::time::Duration::from_secs(config.connect_timeout_secs))
                .build()?,
        });

        info!("Phantom proxy listening on 127.0.0.1:{}", actual_port);

        let handle = tokio::spawn(async move {
            run_server(listener, state, shutdown_rx).await;
        });

        Ok(Self {
            port: actual_port,
            shutdown_tx,
            handle,
        })
    }

    /// Get the port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Generate the proxy authentication token for this session.
    pub fn generate_proxy_token() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Shut down the proxy server gracefully.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.handle.await;
        info!("Phantom proxy shut down");
    }
}

struct ProxyState {
    registry: ServiceRegistry,
    interceptor: Interceptor,
    proxy_token: String,
    max_body_size: usize,
    http_client: reqwest::Client,
}

async fn run_server(
    listener: TcpListener,
    state: Arc<ProxyState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        debug!("Connection from {}", addr);
                        let state = state.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            if let Err(e) = http1::Builder::new()
                                .serve_connection(
                                    io,
                                    service_fn(move |req| {
                                        handle_request(req, state.clone())
                                    }),
                                )
                                .await
                            {
                                debug!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();

    debug!("{} {}{}", method, path, query);

    // Health check endpoint
    if path == "/phantom/health" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(
                r#"{"status":"ok","service":"phantom-proxy"}"#,
            )))
            .unwrap());
    }

    // Verify proxy token (defense-in-depth — prevents other local processes from using the proxy)
    if !state.proxy_token.is_empty() {
        let provided_token = req
            .headers()
            .get("x-phantom-proxy-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if provided_token != state.proxy_token {
            // Also check query param as fallback (for clients that can't set custom headers)
            let query_token = req
                .uri()
                .query()
                .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("phantom_token=")))
                .unwrap_or("");

            if query_token != state.proxy_token {
                warn!("Rejected request without valid proxy token from {}", path);
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Full::new(Bytes::from(
                        r#"{"error":"missing or invalid proxy token"}"#,
                    )))
                    .unwrap());
            }
        }
    }

    // Match the route
    let (route, remainder) = match state.registry.match_route(&path) {
        Some(matched) => matched,
        None => {
            warn!("No route found for path: {}", path);
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from(format!(
                    r#"{{"error":"no route for path: {}","hint":"check .phantom.toml service configuration"}}"#,
                    path
                ))))
                .unwrap());
        }
    };

    let target_url = format!("{}{}{}", route.target_base, remainder, query);
    debug!("Proxying to: {}", target_url);

    // Build the outgoing request
    let mut outgoing = state.http_client.request(method.clone(), &target_url);

    // Copy and transform headers
    for (name, value) in req.headers() {
        // Skip hop-by-hop headers and our custom headers
        let name_str = name.as_str();
        if matches!(
            name_str,
            "host"
                | "connection"
                | "transfer-encoding"
                | "x-phantom-proxy-token"
                | "content-length"
        ) {
            continue;
        }

        if let Ok(value_str) = value.to_str() {
            // Replace phantom tokens in header values
            let (replaced_value, did_replace) = state.interceptor.replace_in_str(value_str);
            if did_replace {
                debug!("Replaced phantom token in header: {}", name_str);
            }
            outgoing = outgoing.header(name_str, replaced_value);
        } else {
            outgoing = outgoing.header(name, value.clone());
        }
    }

    // Read body with size limit enforced during read (prevents OOM on large payloads)
    let limited_body = http_body_util::Limited::new(req.into_body(), state.max_body_size);
    let body_bytes = match limited_body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("length limit exceeded") {
                warn!(
                    "Request body too large (limit: {} bytes)",
                    state.max_body_size
                );
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::from(format!(
                        r#"{{"error":"request body too large","limit":{}}}"#,
                        state.max_body_size
                    ))))
                    .unwrap());
            }
            error!("Failed to read request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(
                    r#"{"error":"failed to read request body"}"#,
                )))
                .unwrap());
        }
    };

    if !body_bytes.is_empty() {
        let (replaced_body, did_replace) = state.interceptor.replace_in_bytes(&body_bytes);
        if did_replace {
            debug!("Replaced phantom token(s) in request body");
        }
        outgoing = outgoing.body(replaced_body);
    }

    // Send the request
    let response = match outgoing.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Upstream request failed: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!(
                    r#"{{"error":"upstream request failed","details":"{}"}}"#,
                    e
                ))))
                .unwrap());
        }
    };

    // Build the response back to the client
    let status = response.status();
    let mut builder = Response::builder().status(status);

    // Copy response headers
    for (name, value) in response.headers() {
        let name_str = name.as_str();
        if matches!(name_str, "transfer-encoding" | "connection") {
            continue;
        }
        builder = builder.header(name, value);
    }

    let response_body = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read response body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(
                    r#"{"error":"failed to read upstream response"}"#,
                )))
                .unwrap());
        }
    };

    debug!("Response: {} ({} bytes)", status, response_body.len());

    Ok(builder.body(Full::new(response_body)).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interceptor::Interceptor;
    use crate::services::{ServiceRegistry, ServiceRoute};
    use std::collections::HashMap;

    fn test_state() -> (ServiceRegistry, Interceptor) {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "test".to_string(),
            target_base: "https://httpbin.org".to_string(),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });

        let mut mappings = HashMap::new();
        mappings.insert(
            "phm_testtoken1234".to_string(),
            "real-secret-value".to_string(),
        );
        let interceptor = Interceptor::new(mappings);

        (registry, interceptor)
    }

    #[tokio::test]
    async fn test_server_starts_and_stops() {
        let (registry, interceptor) = test_state();
        let config = ProxyConfig {
            port: 0, // ephemeral
            proxy_token: String::new(),
            ..ProxyConfig::default()
        };

        let server = ProxyServer::start(config, registry, interceptor)
            .await
            .unwrap();

        assert!(server.port() > 0);

        // Health check
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{}/phantom/health", server.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("ok"));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_unknown_route_returns_404() {
        let (registry, interceptor) = test_state();
        let config = ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            ..ProxyConfig::default()
        };

        let server = ProxyServer::start(config, registry, interceptor)
            .await
            .unwrap();

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{}/unknown/path", server.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_replaces_phantom_token_in_header() {
        // Start mock upstream server
        let mock = crate::test_server::MockServer::start().await;

        // Set up proxy pointing to mock server
        let phantom_token = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
        let real_secret = "sk-real-openai-key-12345";

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });

        let mut mappings = HashMap::new();
        mappings.insert(phantom_token.to_string(), real_secret.to_string());
        let interceptor = Interceptor::new(mappings);

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

        // Send request through proxy with phantom token in Authorization header
        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/testapi/v1/models",
                proxy.port()
            ))
            .header("Authorization", format!("Bearer {phantom_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        // Verify the mock received the REAL secret, not the phantom token
        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);

        let received = &requests[0];
        assert_eq!(received.path, "/v1/models");
        let auth_header = received.headers.get("authorization").unwrap();
        assert_eq!(auth_header, &format!("Bearer {real_secret}"));
        assert!(!auth_header.contains("phm_"));

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_replaces_phantom_token_in_body() {
        let mock = crate::test_server::MockServer::start().await;

        let phantom_token = "phm_bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333";
        let real_secret = "sk-ant-real-anthropic-key";

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_KEY".to_string(),
            header: "x-api-key".to_string(),
            header_format: "{secret}".to_string(),
        });

        let mut mappings = HashMap::new();
        mappings.insert(phantom_token.to_string(), real_secret.to_string());
        let interceptor = Interceptor::new(mappings);

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

        // Send POST with phantom token in the JSON body
        let body = format!(
            r#"{{"model":"claude-3","api_key":"{}","prompt":"hello"}}"#,
            phantom_token
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(format!(
                "http://127.0.0.1:{}/testapi/v1/messages",
                proxy.port()
            ))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        // Verify the mock received the real secret in the body
        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);

        let received_body = String::from_utf8(requests[0].body.clone()).unwrap();
        assert!(received_body.contains(real_secret));
        assert!(!received_body.contains("phm_"));

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_preserves_query_params() {
        let mock = crate::test_server::MockServer::start().await;

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });

        let interceptor = Interceptor::new(HashMap::new());

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

        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/testapi/v1/search?q=test&limit=10",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let requests = mock.get_requests();
        assert_eq!(requests[0].path, "/v1/search?q=test&limit=10");

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn test_body_size_limit_returns_413() {
        let mock = crate::test_server::MockServer::start().await;

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });

        let interceptor = Interceptor::new(HashMap::new());

        // Set a tiny body limit (100 bytes)
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: String::new(),
                max_body_size: 100,
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap();

        let client = reqwest::Client::new();

        // Send a request with body exceeding the limit
        let large_body = "x".repeat(200);
        let resp = client
            .post(format!("http://127.0.0.1:{}/testapi/v1/data", proxy.port()))
            .body(large_body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 413);
        let body = resp.text().await.unwrap();
        assert!(body.contains("request body too large"));

        proxy.shutdown().await;
        mock.shutdown().await;
    }
}
