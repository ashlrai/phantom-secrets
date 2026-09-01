use crate::interceptor::Interceptor;
use crate::rate_limiter::{RateLimitConfig, RateLimiter};
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
    /// Allow URL-carried proxy authentication for SDK compatibility.
    ///
    /// When enabled, both `/_phantom/{token}/` path auth and the legacy
    /// `phantom_token` query-param auth are accepted. Disabled by default so
    /// proxy session tokens do not end up in URLs.
    pub allow_query_token_auth: bool,
    /// Rate-limit configuration. Defaults to env-var-driven values.
    pub rate_limit: RateLimitConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 0,
            proxy_token: String::new(),
            max_body_size: 10 * 1024 * 1024, // 10MB
            upstream_timeout_secs: 30,
            connect_timeout_secs: 5,
            allow_query_token_auth: false,
            rate_limit: RateLimitConfig::from_env(),
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
            rate_limiter: RateLimiter::new(config.rate_limit),
            proxy_token: config.proxy_token,
            allow_query_token_auth: config.allow_query_token_auth,
            max_body_size: config.max_body_size,
            http_client: reqwest::Client::builder()
                .danger_accept_invalid_certs(false)
                // Credential-bearing upstream requests must never inherit an
                // agent-controlled HTTP(S)/ALL_PROXY redirect.
                .no_proxy()
                // Credential-bearing custom headers survive cross-origin
                // redirects in some HTTP stacks. Never follow upstream
                // redirects inside the secret-injecting proxy.
                .redirect(reqwest::redirect::Policy::none())
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
    rate_limiter: RateLimiter,
    proxy_token: String,
    allow_query_token_auth: bool,
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

/// Accept only an absent `Content-Encoding` header or exactly one `identity`
/// header. Response scrubbing operates on the bytes returned by reqwest, so
/// forwarding any encoded representation would let compressed content bypass
/// the value scanner before a downstream client decodes it.
fn upstream_response_is_identity_encoded(headers: &reqwest::header::HeaderMap) -> bool {
    let mut encodings = headers.get_all(reqwest::header::CONTENT_ENCODING).iter();

    let Some(encoding) = encodings.next() else {
        return true;
    };

    encodings.next().is_none()
        && encoding
            .to_str()
            .map(|value| value.trim().eq_ignore_ascii_case("identity"))
            .unwrap_or(false)
}

fn unsupported_upstream_encoding_response() -> Response<BoxBody> {
    let mut response = error_response(
        StatusCode::BAD_GATEWAY,
        r#"{"error":"unsupported_upstream_content_encoding"}"#,
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().clone();
    let original_path = req.uri().path().to_string();
    let (path, path_token) = strip_path_proxy_token(&original_path);
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

        let valid_header_token = constant_time_eq(provided_token, &state.proxy_token);
        let valid_path_token = state.allow_query_token_auth
            && path_token
                .as_deref()
                .map(|token| constant_time_eq(token, &state.proxy_token))
                .unwrap_or(false);

        if !valid_header_token && !valid_path_token {
            // URL-carried auth is intentionally opt-in because URLs are often
            // logged by clients and shells.
            let query_token = req
                .uri()
                .query()
                .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("phantom_token=")))
                .unwrap_or("");

            if !state.allow_query_token_auth || !constant_time_eq(query_token, &state.proxy_token) {
                warn!(
                    "Rejected request without valid proxy token from {}",
                    original_path
                );
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

    // ── Rate-limit / anomaly detection ──────────────────────────────────────
    // Record the access against the matched route's secret key and classify.
    // Alert-class requests are rejected with 429; caution/normal pass through.
    {
        use crate::rate_limiter::AnomalyClass;
        let decision = state.rate_limiter.record(&route.secret_key);
        match decision.class {
            AnomalyClass::Alert => {
                warn!(
                    "Rate limit exceeded for secret '{}': {}/10s per-secret, {}/10s total (score {})",
                    route.secret_key,
                    decision.per_secret_10s,
                    decision.total_10s,
                    decision.anomaly_score,
                );
                let mut resp = error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    format!(
                        r#"{{"error":"rate limit exceeded","secret_key":"{}","anomaly_class":"alert","per_secret_10s":{},"total_10s":{},"anomaly_score":{}}}"#,
                        route.secret_key,
                        decision.per_secret_10s,
                        decision.total_10s,
                        decision.anomaly_score,
                    ),
                );
                resp.headers_mut().insert(
                    "x-phantom-anomaly-class",
                    hyper::header::HeaderValue::from_static("alert"),
                );
                resp.headers_mut().insert(
                    "x-phantom-anomaly-score",
                    hyper::header::HeaderValue::from_str(&decision.anomaly_score.to_string())
                        .unwrap_or(hyper::header::HeaderValue::from_static("100")),
                );
                resp.headers_mut()
                    .insert("retry-after", hyper::header::HeaderValue::from_static("10"));
                return Ok(resp);
            }
            AnomalyClass::Caution => {
                warn!(
                    "Elevated access rate for secret '{}': {}/10s per-secret (score {})",
                    route.secret_key, decision.per_secret_10s, decision.anomaly_score,
                );
            }
            AnomalyClass::Normal => {
                debug!(
                    "Rate check ok for '{}': {}/10s (score {})",
                    route.secret_key, decision.per_secret_10s, decision.anomaly_score,
                );
            }
        }
        // Emit audit event for caution/alert (best-effort, non-blocking).
        if decision.class != AnomalyClass::Normal {
            let event = phantom_core::audit::RateLimitEvent {
                secret_key: route.secret_key.clone(),
                per_secret_10s: decision.per_secret_10s,
                total_10s: decision.total_10s,
                per_secret_60s: decision.per_secret_60s,
                anomaly_score: decision.anomaly_score,
                anomaly_class: match decision.class {
                    AnomalyClass::Caution => phantom_core::audit::AnomalyClass::Caution,
                    AnomalyClass::Alert => phantom_core::audit::AnomalyClass::Alert,
                    AnomalyClass::Normal => phantom_core::audit::AnomalyClass::Normal,
                },
                ts: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };
            event.emit();
        }
    }
    // ────────────────────────────────────────────────────────────────────────

    // Build the outgoing request
    let mut outgoing = state.http_client.request(method.clone(), &target_url);

    // If the route names a vault secret, inject its formatted auth header
    // server-side. Lets clients skip threading phantom tokens through their
    // own request setup entirely.
    let configured_auth_header = state
        .interceptor
        .format_header_for_secret_key(&route.header_format, &route.secret_key);
    let Some(configured_auth_header) = configured_auth_header else {
        warn!("Route credential unavailable for service {}", route.name);
        return Ok(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"route credential unavailable"}"#,
        ));
    };

    // Copy client headers without resolving phantom tokens. The route's exact
    // configured auth header is always removed below and, when the configured
    // vault secret exists, replaced only with the route-owned value. This
    // prevents client-controlled headers (including Cookie/X-API-Key) from
    // turning an otherwise legitimate upstream route into an exfiltration
    // channel.
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        if matches!(
            name_str,
            "host"
                | "connection"
                | "transfer-encoding"
                | "te"
                | "accept-encoding"
                | "x-phantom-proxy-token"
                | "content-length"
        ) {
            continue;
        }
        // The client never controls the route-owned auth header. A missing
        // vault mapping was rejected above before any upstream request.
        if name_str.eq_ignore_ascii_case(&route.header) {
            continue;
        }

        outgoing = outgoing.header(name, value.clone());
    }

    debug!(
        "Injected configured auth header '{}' for service {}",
        route.header, route.name
    );
    outgoing = outgoing.header(route.header.as_str(), configured_auth_header);

    // Response scrubbing is defined over identity bytes. Never forward the
    // client's compression preferences to the upstream.
    outgoing = outgoing.header(reqwest::header::ACCEPT_ENCODING, "identity");

    // Buffer every request body before contacting the upstream. This is a
    // deliberate atomicity boundary: streaming a prefix and then discovering
    // that the body exceeds the cap can cause an upstream mutation to execute
    // on truncated input. The buffer remains strictly bounded.
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
        // Client-controlled request bodies are always forwarded byte-for-byte.
        // Credentials are injected only through the fixed route-owned header.
        outgoing = outgoing.body(body_bytes);
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

    // An upstream may ignore `Accept-Encoding: identity`. Reject encoded
    // responses before copying headers or consuming/streaming any body bytes;
    // stripping Content-Encoding alone would forward an unsafe representation.
    if !upstream_response_is_identity_encoded(response.headers()) {
        warn!(
            "Rejected encoded upstream response for service {}",
            route.name
        );
        return Ok(unsupported_upstream_encoding_response());
    }

    // Build the response back to the client
    let status = response.status();
    let mut builder = Response::builder().status(status);

    // Capture response content-type before consuming the response for its body.
    // Used by ResponseScrubber to apply SSE line-level parsing vs. generic scan.
    let response_content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Copy response headers (skip hop-by-hop and content-length since we stream)
    let is_streaming = response
        .headers()
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("chunked"))
        .unwrap_or(false)
        || response_content_type
            .as_deref()
            .map(|v| v.contains("text/event-stream"))
            .unwrap_or(false);

    let resp_scrubber = state.interceptor.to_response_scrubber();
    for (name, value) in response.headers() {
        let name_str = name.as_str();
        // Drop content-length: streaming uses chunked transfer, non-streaming may need
        // recalculation after response scrubbing (phantom tokens differ in length)
        if matches!(
            name_str,
            "transfer-encoding" | "connection" | "content-length" | "content-encoding"
        ) {
            continue;
        }
        let Ok(value_text) = value.to_str() else {
            warn!("Dropped non-text upstream response header {}", name_str);
            continue;
        };
        let (scrubbed_value, scrub_event) = resp_scrubber.scrub_header(name_str, value_text);
        if scrub_event.scrubbed {
            debug!(
                "Scrubbed credential material from response header {}",
                name_str
            );
        }
        builder = builder.header(name, scrubbed_value);
    }

    if is_streaming {
        // Stream the response body chunk-by-chunk (critical for SSE/streaming APIs).
        // ResponseScrubber performs content-aware, overlap-safe redaction for both
        // exact vault values and recognized unmanaged credential formats.
        debug!("Streaming response: {}", status);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(32);

        let resp_scrubber = state.interceptor.to_response_scrubber();
        let resp_ct = response_content_type.clone();
        let byte_stream = response.bytes_stream();
        tokio::spawn(async move {
            tokio::pin!(byte_stream);
            let mut scrub_carry: Vec<u8> = Vec::new();

            while let Some(chunk_result) = byte_stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        let (scrubbed, scrub_event) =
                            resp_scrubber.scrub_chunk(resp_ct.as_deref(), &mut scrub_carry, &chunk);
                        if scrub_event.scrubbed {
                            debug!(
                                "ResponseScrubber intercepted leak(s) in streaming chunk \
                                 ({} events)",
                                scrub_event.leak_events.len()
                            );
                        }

                        if !scrubbed.is_empty()
                            && tx
                                .send(Ok(Frame::data(Bytes::from(scrubbed))))
                                .await
                                .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Upstream stream error: {}", e);
                        break;
                    }
                }
            }

            let (scrubbed, _) = resp_scrubber.flush_carry(resp_ct.as_deref(), scrub_carry);
            if !scrubbed.is_empty() {
                let _ = tx.send(Ok(Frame::data(Bytes::from(scrubbed)))).await;
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let body = BoxBody::Right(StreamBody::new(stream));
        Ok(builder.body(body).unwrap())
    } else {
        // Non-streaming: buffer, scrub secrets, and forward. Apply the same
        // hard byte cap used for inbound bodies so a compromised upstream
        // cannot exhaust the local proxy before redaction runs.
        let mut response_body = Vec::new();
        let mut response_stream = response.bytes_stream();
        while let Some(chunk_result) = response_stream.next().await {
            let chunk = match chunk_result {
                Ok(chunk) => chunk,
                Err(e) => {
                    error!("Failed to read response body: {}", e);
                    return Ok(error_response(
                        StatusCode::BAD_GATEWAY,
                        r#"{"error":"failed to read upstream response"}"#,
                    ));
                }
            };
            let Some(next_len) = response_body.len().checked_add(chunk.len()) else {
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    r#"{"error":"upstream response too large"}"#,
                ));
            };
            if next_len > state.max_body_size {
                warn!(
                    "Upstream response too large for service {} (limit: {} bytes)",
                    route.name, state.max_body_size
                );
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    format!(
                        r#"{{"error":"upstream response too large","limit":{}}}"#,
                        state.max_body_size
                    ),
                ));
            }
            response_body.extend_from_slice(&chunk);
        }

        let (final_body, scrub_event) =
            resp_scrubber.scrub_buffered(response_content_type.as_deref(), &response_body);
        if scrub_event.scrubbed {
            debug!(
                "ResponseScrubber intercepted leak(s) in buffered response ({} events)",
                scrub_event.leak_events.len()
            );
        }

        // Always set content-length from the final body (may differ after scrubbing).
        let final_body = Bytes::from(final_body);
        debug!("Response: {} ({} bytes)", status, final_body.len());
        let builder = builder.header("content-length", final_body.len().to_string());
        Ok(builder.body(BoxBody::Left(Full::new(final_body))).unwrap())
    }
}

fn strip_path_proxy_token(path: &str) -> (String, Option<String>) {
    let mut parts: Vec<&str> = path.split('/').collect();
    if let Some(idx) = parts.iter().position(|part| *part == "_phantom") {
        if let Some(token) = parts.get(idx + 1).copied() {
            let token = token.to_string();
            parts.drain(idx..=idx + 1);
            let stripped = parts.join("/");
            let stripped = if stripped.is_empty() {
                "/".to_string()
            } else {
                stripped
            };
            return (stripped, Some(token));
        }
    }
    (path.to_string(), None)
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

    #[test]
    fn credential_transport_disables_ambient_forward_proxies() {
        let source = include_str!("server.rs");
        assert!(source.contains(".no_proxy()"));
        assert!(source.contains(".danger_accept_invalid_certs(false)"));
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
    async fn test_proxy_requires_header_token_by_default() {
        let (registry, interceptor) = test_state();
        let token = ProxyServer::generate_proxy_token();
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: token.clone(),
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap();

        let client = reqwest::Client::new();
        let query_resp = client
            .get(format!(
                "http://127.0.0.1:{}/phantom/health?phantom_token={token}",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(query_resp.status(), 401);

        let header_resp = client
            .get(format!("http://127.0.0.1:{}/phantom/health", proxy.port()))
            .header("x-phantom-proxy-token", token.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(header_resp.status(), 200);

        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn external_shutdown_endpoint_is_not_exposed() {
        let (registry, interceptor) = test_state();
        let token = ProxyServer::generate_proxy_token();
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: token.clone(),
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap();
        let client = reqwest::Client::new();

        let unauthenticated = client
            .post(format!(
                "http://127.0.0.1:{}/phantom/shutdown",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", "wrong-token")
            .send()
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), 401);

        let authenticated = client
            .post(format!(
                "http://127.0.0.1:{}/phantom/shutdown",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", token.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(authenticated.status(), 404);

        let health = client
            .get(format!("http://127.0.0.1:{}/phantom/health", proxy.port()))
            .header("x-phantom-proxy-token", token)
            .send()
            .await
            .unwrap();
        assert_eq!(health.status(), 200, "owning handle must remain live");

        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_path_token_requires_compatibility_mode() {
        let (registry, interceptor) = test_state();
        let token = ProxyServer::generate_proxy_token();
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: token.clone(),
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
                "http://127.0.0.1:{}/phantom/_phantom/{token}/health",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_query_token_requires_compatibility_mode() {
        let (registry, interceptor) = test_state();
        let token = ProxyServer::generate_proxy_token();
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: token.clone(),
                allow_query_token_auth: true,
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
                "http://127.0.0.1:{}/phantom/health?phantom_token={token}",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_accepts_path_token_and_strips_before_routing() {
        let mock = crate::test_server::MockServer::start().await;
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "test".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });
        let mut named = HashMap::new();
        named.insert("TEST_API_KEY".to_string(), "real-secret-value".to_string());
        let interceptor = Interceptor::new_with_named(HashMap::new(), named);
        let token = ProxyServer::generate_proxy_token();
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: token.clone(),
                allow_query_token_auth: true,
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
                "http://127.0.0.1:{}/test/_phantom/{token}/headers",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/headers");
        assert_eq!(
            requests[0].headers.get("authorization").unwrap(),
            "Bearer real-secret-value"
        );
        assert!(!requests[0].headers.contains_key("x-phantom-proxy-token"));

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[test]
    fn test_strip_path_proxy_token() {
        assert_eq!(
            strip_path_proxy_token("/openai/_phantom/token/v1/models"),
            ("/openai/v1/models".to_string(), Some("token".to_string()))
        );
        assert_eq!(
            strip_path_proxy_token("/openai/v1/models"),
            ("/openai/v1/models".to_string(), None)
        );
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
    async fn test_proxy_ignores_client_auth_token_and_injects_route_secret() {
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
        mappings.insert(
            phantom_token.to_string(),
            ("TEST_API_KEY".to_string(), real_secret.to_string()),
        );
        let interceptor = Interceptor::new_scoped(
            mappings,
            HashMap::from([("TEST_API_KEY".to_string(), real_secret.to_string())]),
        );

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

        // A client-provided route auth header is discarded. The upstream sees
        // only the fixed route-owned credential injected by the proxy.
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

        // Verify the mock received the route-owned secret, not because the
        // client token was resolved.
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
    async fn test_proxy_never_replaces_phantom_token_in_body() {
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
        mappings.insert(
            phantom_token.to_string(),
            ("TEST_KEY".to_string(), real_secret.to_string()),
        );
        let interceptor = Interceptor::new_scoped(
            mappings,
            HashMap::from([("TEST_KEY".to_string(), real_secret.to_string())]),
        );

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

        // The body is byte-identical and never contains the real secret.
        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);

        let received_body = String::from_utf8(requests[0].body.clone()).unwrap();
        assert!(received_body.contains(phantom_token));
        assert!(!received_body.contains(real_secret));

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn cross_route_token_never_reaches_upstream_as_a_secret() {
        let mock = crate::test_server::MockServer::start().await;
        let openai_token = "phm_1111111122222222333333334444444455555555666666667777777788888888";
        let stripe_token = "phm_aaaaaaaa11111111bbbbbbbb22222222cccccccc33333333dddddddd44444444";
        let stripe_secret = "sk_live_cross_route_must_not_leak";

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "openai".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "OPENAI_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });
        let mappings = HashMap::from([
            (
                openai_token.to_string(),
                ("OPENAI_API_KEY".to_string(), "sk-openai-real".to_string()),
            ),
            (
                stripe_token.to_string(),
                ("STRIPE_SECRET_KEY".to_string(), stripe_secret.to_string()),
            ),
        ]);
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: String::new(),
                ..ProxyConfig::default()
            },
            registry,
            Interceptor::new_scoped(
                mappings,
                HashMap::from([("OPENAI_API_KEY".to_string(), "sk-openai-real".to_string())]),
            ),
        )
        .await
        .unwrap();
        let client = reqwest::Client::new();
        client
            .post(format!("http://127.0.0.1:{}/openai/header", proxy.port()))
            .header("Authorization", format!("Bearer {stripe_token}"))
            .send()
            .await
            .unwrap();
        client
            .post(format!("http://127.0.0.1:{}/openai/json", proxy.port()))
            .header("content-type", "application/json")
            .body(format!(r#"{{"api_key":"{stripe_token}"}}"#))
            .send()
            .await
            .unwrap();
        client
            .post(format!("http://127.0.0.1:{}/openai/text", proxy.port()))
            .header("content-type", "text/plain")
            .body(format!("credential={stripe_token}"))
            .send()
            .await
            .unwrap();
        client
            .post(format!("http://127.0.0.1:{}/openai/form", proxy.port()))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("client_secret={stripe_token}&grant_type=test"))
            .send()
            .await
            .unwrap();

        let requests = mock.get_requests();
        assert_eq!(requests.len(), 4);
        assert_eq!(
            requests[0].headers.get("authorization"),
            Some(&"Bearer sk-openai-real".to_string())
        );
        assert!(String::from_utf8_lossy(&requests[1].body).contains(stripe_token));
        assert!(String::from_utf8_lossy(&requests[2].body).contains(stripe_token));
        assert!(String::from_utf8_lossy(&requests[3].body).contains(stripe_token));
        for request in requests {
            assert!(!String::from_utf8_lossy(&request.body).contains(stripe_secret));
            assert!(request
                .headers
                .values()
                .all(|value| !value.contains(stripe_secret)));
        }
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
        mappings.insert(
            phantom_token.to_string(),
            ("TEST_KEY".to_string(), real_secret.to_string()),
        );
        let interceptor = Interceptor::new_scoped(
            mappings,
            HashMap::from([("TEST_KEY".to_string(), real_secret.to_string())]),
        );

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
    async fn test_proxy_never_resolves_client_controlled_headers() {
        // A prompt-controlled client can set auth-looking headers. Those
        // headers remain inert; only the matched route's configured auth
        // header receives a real credential.
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
        mappings.insert(
            phantom_token.to_string(),
            ("TEST_KEY".to_string(), real_secret.to_string()),
        );
        let interceptor = Interceptor::new_scoped(
            mappings,
            HashMap::from([("TEST_KEY".to_string(), real_secret.to_string())]),
        );

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
            .header("Cookie", format!("session={phantom_token}"))
            .header("X-API-Key", phantom_token)
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
        for header in ["cookie", "x-api-key"] {
            let value = requests[0].headers.get(header).unwrap();
            assert!(
                value.contains(phantom_token),
                "{header} was rewritten: {value}"
            );
            assert!(
                !value.contains(real_secret),
                "real secret leaked into {header}"
            );
        }
        assert_eq!(
            requests[0].headers.get("authorization").unwrap(),
            &format!("Bearer {real_secret}")
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
    async fn missing_route_secret_drops_client_auth_instead_of_forwarding_it() {
        let mock = crate::test_server::MockServer::start().await;

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "MISSING_KEY".to_string(),
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
            Interceptor::new_with_named(HashMap::new(), HashMap::new()),
        )
        .await
        .unwrap();

        let client_token = "phm_ffff1111eeee2222dddd3333cccc4444bbbb5555aaaa6666ffff1111eeee2222";
        let resp = reqwest::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/testapi/v1/models",
                proxy.port()
            ))
            .header("Authorization", format!("Bearer {client_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let requests = mock.get_requests();
        assert!(requests.is_empty(), "missing credential contacted upstream");

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

        let interceptor = Interceptor::new_with_named(
            HashMap::new(),
            HashMap::from([("KEY".to_string(), "query-test-secret".to_string())]),
        );

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

        let interceptor = Interceptor::new_with_named(
            HashMap::new(),
            HashMap::from([("KEY".to_string(), "size-test-secret".to_string())]),
        );

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

        // Exercise the formerly streaming text path with a chunked body. The
        // proxy must reject the complete request atomically, before opening an
        // upstream request or forwarding a truncated prefix.
        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
        body_tx.send(Ok(Bytes::from("x".repeat(60)))).await.unwrap();
        body_tx.send(Ok(Bytes::from("y".repeat(60)))).await.unwrap();
        drop(body_tx);
        let large_body =
            reqwest::Body::wrap_stream(tokio_stream::wrappers::ReceiverStream::new(body_rx));
        let resp = client
            .post(format!("http://127.0.0.1:{}/testapi/v1/data", proxy.port()))
            .header("content-type", "text/plain")
            .body(large_body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 413);
        let body = resp.text().await.unwrap();
        assert!(body.contains("request body too large"));
        assert!(
            mock.get_requests().is_empty(),
            "oversized request must make zero upstream calls"
        );

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_does_not_follow_upstream_redirects() {
        let redirect_target = crate::test_server::MockServer::start().await;
        let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_port = redirect_listener.local_addr().unwrap().port();
        let target_url = format!(
            "http://127.0.0.1:{}/credential-capture",
            redirect_target.port
        );
        let redirect_handle = tokio::spawn(async move {
            let (stream, _) = redirect_listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |_req| {
                        let location = target_url.clone();
                        async move {
                            Ok::<_, hyper::Error>(
                                hyper::Response::builder()
                                    .status(StatusCode::FOUND)
                                    .header("location", location)
                                    .body(http_body_util::Full::new(Bytes::new()))
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .unwrap();
        });

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "redirectapi".to_string(),
            target_base: format!("http://127.0.0.1:{redirect_port}"),
            secret_key: "REDIRECT_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });
        let mut named = HashMap::new();
        named.insert(
            "REDIRECT_KEY".to_string(),
            "sk-must-not-cross-redirect".to_string(),
        );
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: String::new(),
                ..ProxyConfig::default()
            },
            registry,
            Interceptor::new_with_named(HashMap::new(), named),
        )
        .await
        .unwrap();

        // Disable redirects on the caller too, so the assertion observes the
        // proxy's upstream response rather than following Location itself.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = client
            .get(format!(
                "http://127.0.0.1:{}/redirectapi/v1/start",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);
        assert!(response.headers().contains_key("location"));
        assert!(
            redirect_target.get_requests().is_empty(),
            "proxy followed a redirect and contacted the credential-capture target"
        );

        drop(response);
        proxy.shutdown().await;
        redirect_handle.abort();
        let _ = redirect_handle.await;
        redirect_target.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // Streaming body tests
    // -----------------------------------------------------------------------

    /// Text bodies are accepted atomically but never opt arbitrary bytes into
    /// secret substitution, even when a token is split across input chunks.
    #[tokio::test]
    async fn text_body_token_split_across_chunks_remains_unsubstituted() {
        let mock = crate::test_server::MockServer::start().await;

        let phantom_token = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
        let real_secret = "sk-streaming-real-secret";

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });

        let mut mappings = HashMap::new();
        mappings.insert(
            phantom_token.to_string(),
            ("TEST_KEY".to_string(), real_secret.to_string()),
        );
        let interceptor = Interceptor::new_scoped(
            mappings,
            HashMap::from([("TEST_KEY".to_string(), real_secret.to_string())]),
        );

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

        // Split the token at position 20 across two body chunks.
        let split_pos = 20;
        let part1 = format!("key={}", &phantom_token[..split_pos]);
        let part2 = format!("{}&extra=value", &phantom_token[split_pos..]);

        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
        body_tx.send(Ok(Bytes::from(part1))).await.unwrap();
        body_tx.send(Ok(Bytes::from(part2))).await.unwrap();
        drop(body_tx);

        let stream = tokio_stream::wrappers::ReceiverStream::new(body_rx);
        let chunked_body = reqwest::Body::wrap_stream(stream);

        let client = reqwest::Client::new();
        let resp = client
            .post(format!(
                "http://127.0.0.1:{}/testapi/v1/upload",
                proxy.port()
            ))
            .header("content-type", "text/plain")
            .body(chunked_body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);

        let received_body = String::from_utf8(requests[0].body.clone()).unwrap();
        assert_eq!(received_body, format!("key={phantom_token}&extra=value"));
        assert!(received_body.contains(phantom_token));
        assert!(!received_body.contains(real_secret));

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    /// SSE response (Content-Type: text/event-stream) containing a real secret
    /// must be redacted before reaching the client.
    #[tokio::test]
    async fn test_sse_response_scrubs_real_secret() {
        let phantom_token = "phm_bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333";
        let real_secret = "sk-sse-real-secret-value";

        let sse_body = format!(
            "data: {{\"key\":\"{real_secret}\"}}

"
        );

        // Minimal SSE upstream.
        let sse_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let sse_listener = tokio::net::TcpListener::bind(sse_addr).await.unwrap();
        let sse_port = sse_listener.local_addr().unwrap().port();
        let sse_body_clone = sse_body.clone();
        let (sse_shutdown_tx, mut sse_shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = sse_listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let body_str = sse_body_clone.clone();
                                tokio::spawn(async move {
                                    let io = hyper_util::rt::TokioIo::new(stream);
                                    let _ = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(
                                            io,
                                            hyper::service::service_fn(move |_req| {
                                                let b = body_str.clone();
                                                async move {
                                                    Ok::<_, hyper::Error>(
                                                        hyper::Response::builder()
                                                            .status(200)
                                                            .header("content-type", "text/event-stream")
                                                            .header("transfer-encoding", "chunked")
                                                            .body(http_body_util::Full::new(
                                                                bytes::Bytes::from(b),
                                                            ))
                                                            .unwrap(),
                                                    )
                                                }
                                            }),
                                        )
                                        .await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                    _ = sse_shutdown_rx.changed() => {
                        if *sse_shutdown_rx.borrow() { break; }
                    }
                }
            }
        });

        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "sseapi".to_string(),
            target_base: format!("http://127.0.0.1:{sse_port}"),
            secret_key: "SSE_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });

        let mut mappings = HashMap::new();
        mappings.insert(phantom_token.to_string(), real_secret.to_string());
        let interceptor = Interceptor::new_with_named(
            mappings,
            HashMap::from([("SSE_KEY".to_string(), real_secret.to_string())]),
        );

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
                "http://127.0.0.1:{}/sseapi/v1/stream",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body_text = resp.text().await.unwrap();

        assert!(
            !body_text.contains(real_secret),
            "real secret leaked through SSE response scrubber: {body_text}"
        );
        assert!(
            body_text.contains("[REDACTED:vault-secret]"),
            "redaction marker not present after SSE response scrub: {body_text}"
        );

        proxy.shutdown().await;
        let _ = sse_shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn test_proxy_scrubs_response_headers_and_unmanaged_body_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let real_secret = "sk-response-header-secret";
        let upstream_secret = real_secret.to_string();
        tokio::spawn(async move {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.unwrap();
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, hyper::service::service_fn(move |_req| {
                            let header_secret = upstream_secret.clone();
                            async move {
                                Ok::<_, hyper::Error>(hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .header("x-debug-secret", header_secret)
                                    .body(http_body_util::Full::new(bytes::Bytes::from(
                                        r#"{"token":"ghp_abcdefghijklmnopqrstuvwxyz1234567890"}"#,
                                    )))
                                    .unwrap())
                            }
                        }))
                        .await;
                }
                _ = shutdown_rx.changed() => {}
            }
        });

        let phantom_token = "phm_dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444eeee5555";
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "responseapi".to_string(),
            target_base: format!("http://127.0.0.1:{upstream_port}"),
            secret_key: "RESPONSE_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });
        let mut mappings = HashMap::new();
        mappings.insert(phantom_token.to_string(), real_secret.to_string());
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: String::new(),
                ..ProxyConfig::default()
            },
            registry,
            Interceptor::new_with_named(
                mappings,
                HashMap::from([("RESPONSE_KEY".to_string(), real_secret.to_string())]),
            ),
        )
        .await
        .unwrap();

        let response = reqwest::get(format!(
            "http://127.0.0.1:{}/responseapi/v1/test",
            proxy.port()
        ))
        .await
        .unwrap();
        assert_eq!(
            response.headers()["x-debug-secret"],
            "[REDACTED:vault-secret]"
        );
        let body = response.text().await.unwrap();
        assert!(!body.contains("ghp_abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(body.contains("[REDACTED:ghp_*]"));

        proxy.shutdown().await;
        let _ = shutdown_tx.send(true);
    }

    /// Binary content-type (application/octet-stream) uses the buffered path
    /// and scoped_body_replace leaves it unchanged — no token substitution.
    #[tokio::test]
    async fn test_binary_content_type_passthrough_unchanged() {
        let mock = crate::test_server::MockServer::start().await;

        let phantom_token = "phm_cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444";
        let real_secret = "sk-binary-real-secret";

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
        let interceptor = Interceptor::new_with_named(
            mappings,
            HashMap::from([("TEST_KEY".to_string(), real_secret.to_string())]),
        );

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

        let binary_body = format!(" {phantom_token}");

        let client = reqwest::Client::new();
        let resp = client
            .post(format!(
                "http://127.0.0.1:{}/testapi/v1/upload",
                proxy.port()
            ))
            .header("content-type", "application/octet-stream")
            .body(binary_body.clone())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);

        let received_body = String::from_utf8_lossy(&requests[0].body);
        assert!(
            !received_body.contains(real_secret),
            "real secret leaked into binary body: {received_body}"
        );
        assert!(
            received_body.contains(phantom_token),
            "phantom token in binary body was altered: {received_body}"
        );

        proxy.shutdown().await;
        mock.shutdown().await;
    }
}
