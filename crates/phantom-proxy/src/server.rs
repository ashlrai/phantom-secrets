use crate::body_scope;
use crate::interceptor::Interceptor;
use crate::services::ServiceRegistry;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_stream::StreamExt;
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
                .redirect(reqwest::redirect::Policy::limited(5))
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

type BoxBody = http_body_util::Either<
    Full<Bytes>,
    StreamBody<tokio_stream::wrappers::ReceiverStream<Result<Frame<Bytes>, std::io::Error>>>,
>;

fn error_response(status: StatusCode, body: impl Into<Bytes>) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .body(BoxBody::Left(Full::new(body.into())))
        .unwrap()
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Strip phantom_token from query before forwarding to upstream
    let query = req
        .uri()
        .query()
        .map(|q| {
            let filtered: Vec<&str> = q
                .split('&')
                .filter(|p| !p.starts_with("phantom_token="))
                .collect();
            if filtered.is_empty() {
                String::new()
            } else {
                format!("?{}", filtered.join("&"))
            }
        })
        .unwrap_or_default();

    debug!("{} {}{}", method, path, query);

    // Verify proxy token (defense-in-depth — prevents other local processes from using the proxy)
    // Token check runs before ALL endpoints, including health check.
    if !state.proxy_token.is_empty() {
        let provided_token = req
            .headers()
            .get("x-phantom-proxy-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !constant_time_eq(provided_token, &state.proxy_token) {
            // Also check query param as fallback (for clients that can't set custom headers)
            let query_token = req
                .uri()
                .query()
                .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("phantom_token=")))
                .unwrap_or("");

            if !constant_time_eq(query_token, &state.proxy_token) {
                warn!("Rejected request without valid proxy token from {}", path);
                return Ok(error_response(
                    StatusCode::UNAUTHORIZED,
                    r#"{"error":"missing or invalid proxy token"}"#,
                ));
            }
        }
    }

    // Health check endpoint (after token verification)
    if path == "/phantom/health" {
        return Ok(error_response(
            StatusCode::OK,
            r#"{"status":"ok","service":"phantom-proxy"}"#,
        ));
    }

    // Match the route
    let (route, remainder) = match state.registry.match_route(&path) {
        Some(matched) => matched,
        None => {
            warn!("No route found for path: {}", path);
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                format!(
                    r#"{{"error":"no route for path: {}","hint":"check .phantom.toml service configuration"}}"#,
                    path
                ),
            ));
        }
    };

    let target_url = format!("{}{}{}", route.target_base, remainder, query);
    debug!("Proxying to: {}", target_url);

    // Capture the request content-type before consuming `req` for its body —
    // we need it to drive content-type-aware body substitution (F9).
    let request_content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Build the outgoing request
    let mut outgoing = state.http_client.request(method.clone(), &target_url);

    // If the route names a vault secret, inject its formatted auth header
    // server-side. Lets clients skip threading phantom tokens through their
    // own request setup entirely.
    let configured_auth_header = state
        .interceptor
        .format_header_for_secret_key(&route.header_format, &route.secret_key);

    // Copy and transform headers. F9: phm-token substitution is restricted to
    // a whitelist of auth-bearing header names plus the per-route configured
    // header. Tokens present in other headers are passed through unchanged
    // and logged — substituting them would turn arbitrary request metadata
    // into a secret-leakage vector.
    for (name, value) in req.headers() {
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
        // Drop any client-provided auth header for this route when we're
        // about to inject our own — avoids ambiguity / double-auth.
        if configured_auth_header.is_some() && name_str.eq_ignore_ascii_case(&route.header) {
            continue;
        }

        if let Ok(value_str) = value.to_str() {
            let header_value = if body_scope::is_allowed_header(name_str, &route.header) {
                let (replaced_value, did_replace) = state.interceptor.replace_in_str(value_str);
                if did_replace {
                    debug!("Replaced phantom token in header: {}", name_str);
                }
                replaced_value
            } else {
                if state.interceptor.contains_phantom_token(value_str) {
                    warn!(
                        "phantom token in non-allowed request header '{}' — not substituted (F9 scope)",
                        name_str
                    );
                }
                value_str.to_string()
            };
            outgoing = outgoing.header(name_str, header_value);
        } else {
            outgoing = outgoing.header(name, value.clone());
        }
    }

    if let Some(header_value) = configured_auth_header {
        debug!(
            "Injected configured auth header '{}' for service {}",
            route.header, route.name
        );
        outgoing = outgoing.header(route.header.as_str(), header_value);
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
                return Ok(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        r#"{{"error":"request body too large","limit":{}}}"#,
                        state.max_body_size
                    ),
                ));
            }
            error!("Failed to read request body: {}", e);
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"failed to read request body"}"#,
            ));
        }
    };

    if !body_bytes.is_empty() {
        // F9: content-type-scoped substitution. JSON bodies get field-level
        // replacement on a whitelist of known-secret fields; other
        // content-types pass through without substitution.
        let (replaced_body, did_replace) = body_scope::scoped_body_replace(
            &state.interceptor,
            request_content_type.as_deref(),
            &body_bytes,
        );
        if did_replace {
            debug!("Replaced phantom token(s) in request body (scoped)");
        }
        outgoing = outgoing.body(replaced_body);
    }

    // Send the request
    let response = match outgoing.send().await {
        Ok(resp) => resp,
        Err(e) => {
            // Log full error for debugging, but sanitize response to avoid leaking internal details
            error!("Upstream request failed for {}: {}", route.name, e);
            let user_msg = if e.is_timeout() {
                "upstream request timed out"
            } else if e.is_connect() {
                "could not connect to upstream service"
            } else {
                "upstream request failed"
            };
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                format!(r#"{{"error":"{user_msg}","service":"{}"}}"#, route.name),
            ));
        }
    };

    // Build the response back to the client
    let status = response.status();
    let mut builder = Response::builder().status(status);

    // Copy response headers (skip hop-by-hop and content-length since we stream)
    let is_streaming = response
        .headers()
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("chunked"))
        .unwrap_or(false)
        || response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("text/event-stream"))
            .unwrap_or(false);

    for (name, value) in response.headers() {
        let name_str = name.as_str();
        // Drop content-length: streaming uses chunked transfer, non-streaming may need
        // recalculation after response scrubbing (phantom tokens differ in length)
        if matches!(
            name_str,
            "transfer-encoding" | "connection" | "content-length"
        ) {
            continue;
        }
        builder = builder.header(name, value);
    }

    if is_streaming {
        // Stream the response body chunk-by-chunk (critical for SSE/streaming APIs)
        // Scrub secrets from each chunk using an overlap window to catch secrets
        // split across chunk boundaries.
        debug!("Streaming response: {}", status);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(32);

        let interceptor = state.interceptor.clone();
        let byte_stream = response.bytes_stream();
        tokio::spawn(async move {
            tokio::pin!(byte_stream);
            let overlap_len = interceptor.max_secret_len().saturating_sub(1);
            let mut carry: Vec<u8> = Vec::new();

            while let Some(chunk_result) = byte_stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        // Build combined buffer: carry from previous chunk + current chunk
                        let mut combined = Vec::with_capacity(carry.len() + chunk.len());
                        combined.extend_from_slice(&carry);
                        combined.extend_from_slice(&chunk);

                        let (scrubbed, did_scrub) = interceptor.scrub_response_bytes(&combined);
                        if did_scrub {
                            debug!("Scrubbed secret(s) from streaming response chunk");
                        }

                        if overlap_len > 0 && scrubbed.len() > overlap_len {
                            // Hold back the last overlap_len bytes for the next iteration
                            let emit_end = scrubbed.len() - overlap_len;
                            let to_emit = &scrubbed[..emit_end];
                            carry = scrubbed[emit_end..].to_vec();
                            if tx
                                .send(Ok(Frame::data(Bytes::copy_from_slice(to_emit))))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        } else if overlap_len > 0 {
                            // Entire scrubbed output fits within the overlap window; carry it all
                            carry = scrubbed;
                        } else {
                            // No secrets registered — no overlap needed
                            carry.clear();
                            if tx
                                .send(Ok(Frame::data(Bytes::from(scrubbed))))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Upstream stream error: {}", e);
                        break;
                    }
                }
            }

            // Flush any remaining carry bytes
            if !carry.is_empty() {
                let (scrubbed, _) = interceptor.scrub_response_bytes(&carry);
                let _ = tx.send(Ok(Frame::data(Bytes::from(scrubbed)))).await;
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let body = BoxBody::Right(StreamBody::new(stream));
        Ok(builder.body(body).unwrap())
    } else {
        // Non-streaming: buffer, scrub secrets, and forward
        let response_body = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read response body: {}", e);
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    r#"{"error":"failed to read upstream response"}"#,
                ));
            }
        };

        // Scrub real secrets from response body to prevent leakage to AI agents
        let (scrubbed_body, did_scrub) = state.interceptor.scrub_response_bytes(&response_body);
        if did_scrub {
            debug!(
                "Scrubbed secret(s) from response body ({} bytes)",
                scrubbed_body.len()
            );
        }

        // Always set content-length from the final body (may differ after scrubbing)
        let final_body = if did_scrub {
            Bytes::from(scrubbed_body)
        } else {
            response_body
        };
        debug!("Response: {} ({} bytes)", status, final_body.len());
        let builder = builder.header("content-length", final_body.len().to_string());
        Ok(builder.body(BoxBody::Left(Full::new(final_body))).unwrap())
    }
}

/// Constant-time string compare for the proxy-auth token. Length mismatch
/// short-circuits (token length is not secret); the byte compare runs in
/// constant time so an attacker colocated on the loopback interface cannot
/// byte-discover the token via response-timing side-channels.
fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interceptor::Interceptor;
    use crate::services::{ServiceRegistry, ServiceRoute};
    use std::collections::HashMap;

    #[test]
    fn test_constant_time_eq_matches_on_equal() {
        let t = "phm_".to_string() + &"a".repeat(64);
        assert!(constant_time_eq(&t, &t));
    }

    #[test]
    fn test_constant_time_eq_rejects_differing_byte() {
        let a = "phm_".to_string() + &"a".repeat(64);
        let mut b = a.clone();
        b.pop();
        b.push('b');
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_rejects_length_mismatch() {
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "a"));
        assert!(!constant_time_eq("a", ""));
    }

    #[test]
    fn test_constant_time_eq_matches_empty() {
        // Both empty is a match; the call site guards this separately by
        // checking `!state.proxy_token.is_empty()` before invoking compare.
        assert!(constant_time_eq("", ""));
    }

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
    async fn test_proxy_does_not_replace_phantom_token_in_disallowed_body_field() {
        // F9 regression: a phm token landing in a non-secret JSON field
        // (e.g. "prompt" / message content) must NOT be substituted to the
        // real secret before forwarding upstream.
        let mock = crate::test_server::MockServer::start().await;

        let phantom_token = "phm_cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444";
        let real_secret = "sk-must-not-leak-upstream";

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_KEY".to_string(),
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

        // phm token appears only in `prompt` (chat content), never in an
        // allowed field. The proxy must forward it unchanged.
        let body = format!(
            r#"{{"model":"gpt-4","messages":[{{"role":"user","content":"I saw {phantom_token} in logs"}}]}}"#
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://127.0.0.1:{}/testapi/v1/chat", proxy.port()))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);

        let received_body = String::from_utf8(requests[0].body.clone()).unwrap();
        assert!(
            !received_body.contains(real_secret),
            "real secret leaked into non-allowed body field: {received_body}"
        );
        assert!(
            received_body.contains(phantom_token),
            "phm token should have been forwarded un-substituted: {received_body}"
        );

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_does_not_replace_phantom_token_in_disallowed_header() {
        // F9 regression: a phm token in a non-auth header (e.g. User-Agent)
        // must NOT be substituted to the real secret.
        let mock = crate::test_server::MockServer::start().await;

        let phantom_token = "phm_dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444eeee5555";
        let real_secret = "sk-must-not-leak-in-ua";

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_KEY".to_string(),
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

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{}/testapi/v1/ping", proxy.port()))
            .header("User-Agent", format!("agent/{phantom_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let requests = mock.get_requests();
        let ua = requests[0].headers.get("user-agent").unwrap();
        assert!(
            !ua.contains(real_secret),
            "real secret leaked into User-Agent: {ua}"
        );
        assert!(
            ua.contains(phantom_token),
            "phm token should be forwarded: {ua}"
        );

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_injects_configured_header_without_client_auth() {
        let mock = crate::test_server::MockServer::start().await;

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });

        let mut named = HashMap::new();
        named.insert(
            "TEST_API_KEY".to_string(),
            "sk-real-configured-key".to_string(),
        );
        let interceptor = Interceptor::new_with_named(HashMap::new(), named);

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
                "http://127.0.0.1:{}/testapi/v1/models",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].headers.get("authorization").unwrap(),
            "Bearer sk-real-configured-key"
        );

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
