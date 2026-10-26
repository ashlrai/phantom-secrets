use crate::interceptor::Interceptor;
use crate::rate_limiter::{RateLimitConfig, RateLimiter};
use crate::services::{AuthInjection, ServiceRegistry};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const MAX_CONCURRENT_REQUESTS: usize = 32;
const REQUEST_HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const REQUEST_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const SHUTDOWN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_HTTP1_BUFFER_BYTES: usize = 64 * 1024;
/// Default hard cap for buffered bodies: 32 MiB.
pub const DEFAULT_MAX_BODY_SIZE: usize = 32 * 1024 * 1024;
/// Default budget for body bytes buffered across all in-flight requests:
/// 320 MiB, the worst case under the previous 10 MiB x 32-slot limits. A
/// single request may still use the full per-body cap; only the aggregate is
/// bounded, so raising the per-body cap did not triple worst-case memory.
pub const DEFAULT_MAX_BUFFERED_BYTES: usize = 32 * 10 * 1024 * 1024;

/// Configuration for the proxy server.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Port to listen on (0 = ephemeral)
    pub port: u16,
    /// Session token for proxy authentication (defense-in-depth)
    pub proxy_token: String,
    /// Hard cap in bytes for a buffered request body and for a buffered
    /// (content-length-framed) upstream response (default: 32 MiB, the
    /// Anthropic Messages API request limit; long agent sessions with images
    /// or PDFs exceed 10 MiB).
    pub max_body_size: usize,
    /// Aggregate budget in bytes for request and buffered-response bodies
    /// held by all in-flight requests (default: 320 MiB). A request that
    /// would exceed it is rejected with 503 and `retry-after`.
    pub max_buffered_bytes: usize,
    /// Upstream idle timeout in seconds (default: 600).
    ///
    /// This bounds each wait for upstream bytes (response headers or the next
    /// body chunk), not the whole exchange. A total deadline would cut off
    /// long LLM streams and slow non-streaming reasoning calls that the
    /// official OpenAI and Anthropic SDKs allow for up to 600 seconds.
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
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            upstream_timeout_secs: 600,
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

/// Upstream TLS client config: rustls with the aws-lc-rs provider and the
/// webpki root store. Certificate verification is unchanged from the previous
/// reqwest `rustls-tls` default; only the crypto provider differs.
fn upstream_tls_config() -> rustls::ClientConfig {
    upstream_tls_config_with_extra_roots(&[])
}

/// The upstream client config with additional trust anchors. Production passes
/// none; only the `test-utils` start path below passes a test-local root.
fn upstream_tls_config_with_extra_roots(
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for root in extra_roots {
        roots
            .add(root.clone())
            .expect("test root certificate must parse as a trust anchor");
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("aws-lc-rs provider supports the default TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg
}

/// One TLS key exchange group the proxy's upstream client offers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OfferedKxGroup {
    /// rustls name of the group, for example `X25519MLKEM768` or `X25519`.
    pub name: String,
    /// IANA TLS Supported Groups code point, for example `0x11ec`.
    pub code_point: u16,
}

/// The key exchange groups the proxy's upstream TLS client offers, in offer
/// order (most preferred first). Read from the same provider config the proxy
/// connects with, not from a hard-coded list. What is negotiated with a given
/// upstream also depends on that server.
pub fn upstream_offered_key_exchange_groups() -> Vec<OfferedKxGroup> {
    upstream_tls_config()
        .crypto_provider()
        .kx_groups
        .iter()
        .map(|group| {
            let named = group.name();
            OfferedKxGroup {
                name: format!("{named:?}"),
                code_point: u16::from(named),
            }
        })
        .collect()
}

impl ProxyServer {
    /// Start the proxy server.
    pub async fn start(
        config: ProxyConfig,
        registry: ServiceRegistry,
        interceptor: Interceptor,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::start_with_upstream_tls(config, registry, interceptor, upstream_tls_config()).await
    }

    /// Test-only: start the proxy with its normal upstream TLS config plus
    /// extra trust anchors, so a test can stand up a local TLS upstream with a
    /// self-signed certificate. Not available in release builds.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn start_trusting_test_roots(
        config: ProxyConfig,
        registry: ServiceRegistry,
        interceptor: Interceptor,
        extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::start_with_upstream_tls(
            config,
            registry,
            interceptor,
            upstream_tls_config_with_extra_roots(&extra_roots),
        )
        .await
    }

    async fn start_with_upstream_tls(
        config: ProxyConfig,
        registry: ServiceRegistry,
        interceptor: Interceptor,
        upstream_tls: rustls::ClientConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
        let listener = TcpListener::bind(addr).await?;
        let actual_port = listener.local_addr()?.port();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let state = Arc::new(ProxyState {
            registry,
            interceptor,
            rate_limiter: RateLimiter::new(config.rate_limit),
            request_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
            buffer_budget: Arc::new(Semaphore::new(
                config.max_buffered_bytes.min(Semaphore::MAX_PERMITS),
            )),
            proxy_token: config.proxy_token,
            allow_query_token_auth: config.allow_query_token_auth,
            max_body_size: config.max_body_size,
            http_client: reqwest::Client::builder()
                .danger_accept_invalid_certs(false)
                // aws-lc-rs provider: offers X25519MLKEM768 (post-quantum
                // hybrid) first, with classical groups as fallback.
                .use_preconfigured_tls(upstream_tls)
                // Credential-bearing upstream requests must never inherit an
                // agent-controlled HTTP(S)/ALL_PROXY redirect.
                .no_proxy()
                // Credential-bearing custom headers survive cross-origin
                // redirects in some HTTP stacks. Never follow upstream
                // redirects inside the secret-injecting proxy.
                .redirect(reqwest::redirect::Policy::none())
                // Idle (per-read) deadline, never a total one: a stalled
                // upstream is still cut off, but a healthy SSE stream or a
                // slow reasoning response is not truncated mid-flight.
                .read_timeout(std::time::Duration::from_secs(config.upstream_timeout_secs))
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
    request_slots: Arc<Semaphore>,
    buffer_budget: Arc<Semaphore>,
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
    let connection_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if result.is_err() {
                    warn!("Proxy connection task ended unexpectedly");
                }
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
                            warn!(
                                "Rejected loopback connection from {} because the {}-connection limit is active",
                                addr,
                                MAX_CONCURRENT_CONNECTIONS
                            );
                            drop(stream);
                            continue;
                        };
                        debug!("Connection from {}", addr);
                        let state = state.clone();
                        let mut connection_shutdown = shutdown_rx.clone();
                        connections.spawn(async move {
                            let _permit = permit;
                            let io = TokioIo::new(stream);
                            let mut builder = http1::Builder::new();
                            builder
                                .timer(TokioTimer::new())
                                .header_read_timeout(REQUEST_HEADER_TIMEOUT)
                                .max_buf_size(MAX_HTTP1_BUFFER_BYTES);
                            let mut connection = std::pin::pin!(builder.serve_connection(
                                io,
                                service_fn(move |req| handle_request(req, state.clone())),
                            ));
                            tokio::select! {
                                result = &mut connection => {
                                    if let Err(error) = result {
                                        debug!("Connection error: {error}");
                                    }
                                }
                                changed = connection_shutdown.changed() => {
                                    if changed.is_ok() && *connection_shutdown.borrow() {
                                        connection.as_mut().graceful_shutdown();
                                        match tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, &mut connection).await {
                                            Ok(Err(error)) => debug!("Connection drain error: {error}"),
                                            Err(_) => debug!("Connection drain timed out"),
                                            Ok(Ok(())) => {}
                                        }
                                    }
                                }
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

    let drain_deadline = tokio::time::Instant::now() + SHUTDOWN_DRAIN_TIMEOUT;
    while !connections.is_empty() {
        let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero()
            || tokio::time::timeout(remaining, connections.join_next())
                .await
                .is_err()
        {
            break;
        }
    }
    if !connections.is_empty() {
        warn!(
            "Aborting {} proxy connection(s) that exceeded the shutdown drain deadline",
            connections.len()
        );
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

/// Bytes of the shared buffer budget held by one request until it returns.
struct BufferReservation {
    budget: Arc<Semaphore>,
    held: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl BufferReservation {
    fn new(budget: Arc<Semaphore>) -> Self {
        Self { budget, held: None }
    }

    /// Reserve `bytes` more without waiting; false when the budget is spent.
    fn try_reserve(&mut self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        let Ok(bytes) = u32::try_from(bytes) else {
            return false;
        };
        match self.budget.clone().try_acquire_many_owned(bytes) {
            Ok(permit) => {
                match self.held.as_mut() {
                    Some(held) => held.merge(permit),
                    None => self.held = Some(permit),
                }
                true
            }
            Err(_) => false,
        }
    }
}

fn buffer_budget_exhausted_response() -> Response<BoxBody> {
    warn!("Rejected request because the proxy body buffer budget is exhausted");
    let mut response = error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"proxy body buffer budget is temporarily exhausted","source":"phantom-proxy"}"#,
    );
    response
        .headers_mut()
        .insert("retry-after", hyper::header::HeaderValue::from_static("1"));
    response
}

type BoxBody = http_body_util::Either<
    Full<Bytes>,
    StreamBody<tokio_stream::wrappers::ReceiverStream<Result<Frame<Bytes>, std::io::Error>>>,
>;

/// Every proxy-generated error body is JSON. Label it so SDK clients parse
/// the error instead of surfacing an opaque text blob, and never cache it.
fn error_response(status: StatusCode, body: impl Into<Bytes>) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(BoxBody::Left(Full::new(body.into())))
        .unwrap()
}

/// Why an upstream request failed before any response arrived.
///
/// Built only from error kinds and fixed phrases: the raw error chain can name
/// hosts, addresses, or certificate subjects, so none of it reaches the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamFailure {
    Timeout,
    DnsResolution,
    ConnectionRefused,
    TlsHandshake,
    Connect,
    Other,
}

impl UpstreamFailure {
    fn classify(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            return Self::Timeout;
        }
        let mut source: Option<&(dyn std::error::Error + 'static)> =
            std::error::Error::source(error);
        let mut dns = false;
        let mut tls = false;
        while let Some(current) = source {
            if let Some(io) = current.downcast_ref::<std::io::Error>() {
                match io.kind() {
                    std::io::ErrorKind::ConnectionRefused => return Self::ConnectionRefused,
                    std::io::ErrorKind::TimedOut => return Self::Timeout,
                    _ => {}
                }
            }
            let text = current.to_string().to_ascii_lowercase();
            dns |= text.contains("dns error") || text.contains("failed to lookup address");
            tls |= text.contains("certificate")
                || text.contains("tls")
                || text.contains("handshake")
                || text.contains("invalidcontenttype")
                || text.contains("corrupt message");
            source = current.source();
        }
        if dns {
            Self::DnsResolution
        } else if tls {
            Self::TlsHandshake
        } else if error.is_connect() {
            Self::Connect
        } else {
            Self::Other
        }
    }

    fn error(self) -> &'static str {
        match self {
            Self::Timeout => "upstream request timed out",
            Self::DnsResolution | Self::ConnectionRefused | Self::TlsHandshake | Self::Connect => {
                "could not connect to upstream service"
            }
            Self::Other => "upstream request failed",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::DnsResolution => "dns_resolution_failed",
            Self::ConnectionRefused => "connection_refused",
            Self::TlsHandshake => "tls_handshake_failed",
            Self::Connect => "connect_failed",
            Self::Other => "request_failed",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Timeout => {
                "the upstream did not respond in time; retry, or check network reachability of the service host"
            }
            Self::DnsResolution => {
                "the service host did not resolve; check network/DNS access and the service host in .phantom.toml"
            }
            Self::ConnectionRefused => {
                "nothing accepted the connection at the service host; check the host and port in .phantom.toml"
            }
            Self::TlsHandshake => {
                "the TLS handshake with the service host failed; check that it is an HTTPS endpoint with a valid certificate and that the system clock is correct"
            }
            Self::Connect => {
                "could not open a connection to the service host; check network access and the service host in .phantom.toml"
            }
            Self::Other => "the upstream request failed before a response; retry, then check `phantom doctor`",
        }
    }
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
    debug!(
        "{} {} query_present={}",
        method,
        path,
        req.uri().query().is_some_and(|q| !q.is_empty())
    );

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
                warn!("Rejected request without a valid proxy session token");
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

    // A `_phantom` segment left after stripping the defined-position pair
    // is misplaced URL auth. Refuse it rather than cut it out of the path
    // (which would reach a different upstream endpoint) or forward it (which
    // could carry the proxy session token upstream).
    if path_has_path_auth_segment(&path) {
        warn!("Rejected request path with a misplaced proxy auth segment");
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "error": "request path contains a misplaced proxy auth segment",
                "source": "phantom-proxy",
                "hint": "URL-carried proxy auth is accepted only as /<route>/_phantom/<PHANTOM_PROXY_TOKEN>/ at the start of the path. Use the base URL phantom exec set, or send x-phantom-proxy-token instead.",
            })
            .to_string(),
        ));
    }

    // Refuse any path the outbound URL parser would rewrite. `url`/reqwest
    // resolve `.`/`..` segments, including percent-encoded forms such as
    // `%2e%2e`, so `/openai/../admin` would otherwise leave the route base
    // and carry the route-owned credential to another path on the same
    // upstream host. Encoded separators (`%2f`, `%5c`) and backslashes are
    // refused too, since upstream servers may decode them into segments.
    // This runs before routing, rate accounting and credential lookup, so a
    // refused request never touches the vault or the network.
    if path_has_dot_segment_or_encoded_separator(&path) {
        warn!("Rejected request path containing dot segments or encoded separators");
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "error": "request path contains dot segments or encoded separators",
                "source": "phantom-proxy",
                "hint": "Phantom refuses paths with '.', '..', '%2e', '%2f', '%5c' or '\\' segments so a request can never leave its route's base path. Send the normalized path instead.",
            })
            .to_string(),
        ));
    }

    // Match the route
    let (route, remainder) = match state.registry.match_route(&path) {
        Some(matched) => matched,
        None => {
            warn!("No route found for request path");
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                serde_json::json!({
                    "error": "no route for request path",
                    "hint": "check .phantom.toml service configuration",
                    "routes": state
                        .registry
                        .services()
                        .into_iter()
                        .map(|(name, _)| format!("/{name}"))
                        .collect::<Vec<_>>(),
                })
                .to_string(),
            ));
        }
    };

    // Strip phantom_token and any route-owned credential parameters (for
    // example Gemini's `?key=`) before forwarding to the upstream.
    let owned_slots = route.owned_alternate_slots();
    let query = filter_query(req.uri().query(), owned_slots.query_params);
    let target_url = format!(
        "{}{}{}",
        route.target_base,
        route.upstream_path(remainder),
        query
    );
    debug!("Proxying reviewed route for service {}", route.name);

    let Ok(_request_permit) = state.request_slots.clone().try_acquire_owned() else {
        warn!(
            "Rejected request because the {}-request work limit is active",
            MAX_CONCURRENT_REQUESTS
        );
        let mut response = error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"proxy request capacity is temporarily exhausted","source":"phantom-proxy"}"#,
        );
        response
            .headers_mut()
            .insert("retry-after", hyper::header::HeaderValue::from_static("1"));
        return Ok(response);
    };

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
                    serde_json::json!({
                        "error": "rate limit exceeded",
                        "source": "phantom-proxy",
                        "secret_key": route.secret_key,
                        "anomaly_class": "alert",
                        "per_secret_10s": decision.per_secret_10s,
                        "total_10s": decision.total_10s,
                        "anomaly_score": decision.anomaly_score,
                        "hint": "Phantom's local burst guard rejected this request, not the provider. Retry after the retry-after delay, or raise PHANTOM_RATE_LIMIT_PER_SECRET / PHANTOM_RATE_LIMIT_BURST before phantom exec.",
                    })
                    .to_string(),
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
    // Basic routes keep the client's non-secret username (an account
    // identifier, from the first Authorization header) and replace the
    // password with the vault value. Without a usable username the request
    // is rejected locally: a password-only Basic value is never valid.
    let configured_auth_header = match route.auth_injection() {
        AuthInjection::BasicPassword => {
            let Some(username) = req
                .headers()
                .get(route.header.as_str())
                .and_then(basic_auth_username)
            else {
                warn!(
                    "Rejected Basic-auth request without a usable username for service {}",
                    route.name
                );
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "error": "basic auth username required",
                        "source": "phantom-proxy",
                        "service": route.name,
                        "hint": "This route injects only the password. Send Authorization: Basic base64(<ACCOUNT_SID>:<anything>) with your plain account identifier as the username; Phantom replaces the password with the protected value.",
                    })
                    .to_string(),
                ));
            };
            state
                .interceptor
                .format_basic_auth_for_secret_key(&username, &route.secret_key)
        }
        AuthInjection::Template => state
            .interceptor
            .format_header_for_secret_key(&route.header_format, &route.secret_key)
            .map(Zeroizing::new),
    };
    let Some(configured_auth_header) = configured_auth_header else {
        warn!("Route credential unavailable for service {}", route.name);
        return Ok(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "error": "route credential unavailable",
                "source": "phantom-proxy",
                "service": route.name,
                "secret_key": route.secret_key,
                "hint": "Phantom has no vault value for this route in this session. Protect the key with phantom init or phantom add, then restart phantom exec.",
            })
            .to_string(),
        ));
    };

    // Copy client headers without resolving phantom tokens. The route's exact
    // configured auth header is always removed below and, when the configured
    // vault secret exists, replaced only with the route-owned value. This
    // prevents client-controlled headers (including Cookie/X-API-Key) from
    // turning an otherwise legitimate upstream route into an exfiltration
    // channel.
    let request_connection_named = connection_named_headers(req.headers());
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        if matches!(
            name_str,
            "host" | "accept-encoding" | "x-phantom-proxy-token" | "content-length"
        ) || is_hop_by_hop(name_str, &request_connection_named)
        {
            continue;
        }
        // The client never controls the route-owned auth header. A missing
        // vault mapping was rejected above before any upstream request.
        if name_str.eq_ignore_ascii_case(&route.header) {
            continue;
        }
        // Alternate slots where the upstream accepts the same credential
        // are route-owned as well.
        // A client's own credential there (for example an OAuth bearer) is
        // forwarded; only values carrying a phantom token are dropped.
        if owned_slots
            .headers_carrying_phantom_token
            .iter()
            .any(|owned| name_str.eq_ignore_ascii_case(owned))
            && carries_phantom_token(value.as_bytes())
        {
            continue;
        }

        outgoing = outgoing.header(name, value.clone());
    }

    debug!(
        "Injected configured auth header '{}' for service {}",
        route.header, route.name
    );
    outgoing = outgoing.header(route.header.as_str(), configured_auth_header.as_str());
    // A Basic route sends `base64(username:secret)`, not the literal vault
    // value, so exact and partial-run matching on the vault value alone never
    // sees an upstream echo of it. Scrub the encoded pair this request sent
    // as a managed value too, in response headers and every body path.
    let injected_basic_pair = (route.auth_injection() == AuthInjection::BasicPassword)
        .then(|| configured_auth_header.strip_prefix("Basic "))
        .flatten()
        .map(|encoded| Zeroizing::new(encoded.to_string()));
    drop(configured_auth_header);
    let resp_scrubber = state.interceptor.to_response_scrubber_with_injected(
        injected_basic_pair
            .as_deref()
            .map(|encoded| (route.secret_key.as_str(), encoded.as_str())),
    );
    drop(injected_basic_pair);

    // Response scrubbing is defined over identity bytes. Never forward the
    // client's compression preferences to the upstream.
    outgoing = outgoing.header(reqwest::header::ACCEPT_ENCODING, "identity");

    // Buffer every request body before contacting the upstream. This is a
    // deliberate atomicity boundary: streaming a prefix and then discovering
    // that the body exceeds the cap can cause an upstream mutation to execute
    // on truncated input. The buffer remains strictly bounded.
    //
    // Every buffered byte (request and buffered response) is also charged to
    // a shared budget so the aggregate across concurrent requests stays
    // bounded regardless of the per-body cap.
    let mut reservation = BufferReservation::new(state.buffer_budget.clone());
    let max_body_size = state.max_body_size;
    let collect = async {
        let mut body = req.into_body();
        let mut collected = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| BodyReadError::Read)?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            if collected.len().saturating_add(data.len()) > max_body_size {
                return Err(BodyReadError::TooLarge);
            }
            if !reservation.try_reserve(data.len()) {
                return Err(BodyReadError::Budget);
            }
            collected.extend_from_slice(&data);
        }
        Ok(Bytes::from(collected))
    };
    let body_bytes = match tokio::time::timeout(REQUEST_BODY_TIMEOUT, collect).await {
        Ok(Ok(collected)) => collected,
        Ok(Err(BodyReadError::Budget)) => return Ok(buffer_budget_exhausted_response()),
        Ok(Err(error)) => {
            if error == BodyReadError::TooLarge {
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
            error!("Failed to read request body");
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"failed to read request body"}"#,
            ));
        }
        Err(_) => {
            warn!("Request body deadline exceeded");
            return Ok(error_response(
                StatusCode::REQUEST_TIMEOUT,
                r#"{"error":"request body deadline exceeded"}"#,
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
            let failure = UpstreamFailure::classify(&e);
            error!(
                "Upstream request failed for service {} ({})",
                route.name,
                failure.reason()
            );
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                serde_json::json!({
                    "error": failure.error(),
                    "reason": failure.reason(),
                    "hint": failure.hint(),
                    "service": route.name,
                })
                .to_string(),
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
    //
    // Any body-bearing response without a declared length is streamed:
    // close-delimited (unframed) responses carry neither `content-length`
    // nor `transfer-encoding`, and NDJSON or JSON-array streams are not
    // `text/event-stream`. Buffering those would stall the client until the
    // upstream closed and cap them at `max_body_size`. The streaming scrubber is byte-oriented and holds the
    // same exact-value and credential-format guarantees across every chunk
    // boundary for every content type.
    let has_declared_length = response
        .headers()
        .contains_key(reqwest::header::CONTENT_LENGTH);
    let may_have_body = method != hyper::Method::HEAD
        && !status.is_informational()
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED;
    let is_streaming = response
        .headers()
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("chunked"))
        .unwrap_or(false)
        || response_content_type
            .as_deref()
            .map(|v| v.contains("text/event-stream"))
            .unwrap_or(false)
        || (may_have_body && !has_declared_length);

    // A HEAD response's Content-Length is the length a GET would return
    // (RFC 9110 section 8.6), not the length of the proxy's empty buffered
    // body. Keep the upstream value when it is a well-formed length.
    let head_content_length = if method == hyper::Method::HEAD {
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .map(str::to_string)
    } else {
        None
    };

    // When the client authenticated with the `/<route>/_phantom/<token>/`
    // base URL, mapped upstream URIs are written relative to the request so
    // the client keeps that base without the proxy echoing the token.
    let path_auth_remainder = path_token.as_ref().map(|_| remainder);
    // Upstream relative references resolve against the upstream request URL.
    let upstream_request_url = reqwest::Url::parse(&target_url).ok();
    let scope_uri = |value: &str| {
        scope_upstream_uri_for_client(
            value,
            route,
            upstream_request_url.as_ref(),
            path_auth_remainder,
        )
    };
    let response_connection_named = connection_named_headers(response.headers());
    for (name, value) in response.headers() {
        let name_str = name.as_str();
        // Drop content-length: streaming uses chunked transfer, non-streaming may need
        // recalculation after response scrubbing (phantom tokens differ in length)
        if matches!(name_str, "content-length" | "content-encoding")
            || is_hop_by_hop(name_str, &response_connection_named)
        {
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
        // Every route shares this proxy's one origin, so an upstream cookie
        // must be confined to its own route prefix or a client cookie jar
        // would replay it to every other route's upstream.
        let scrubbed_value = if name == hyper::header::SET_COOKIE {
            match scope_set_cookie_to_route(&scrubbed_value, &route.name) {
                Some(scoped) => scoped,
                None => {
                    warn!(
                        "Dropped upstream Set-Cookie for service {} that cannot be route-scoped",
                        route.name
                    );
                    continue;
                }
            }
        } else if name == hyper::header::LOCATION
            || name == hyper::header::CONTENT_LOCATION
            || name == hyper::header::LINK
        {
            // Every route shares this proxy's one origin, so a redirect, a
            // Content-Location or a Link naming the route's upstream must
            // keep the route prefix, or the client follows it to the wrong
            // local path (possibly another route) or straight to the
            // upstream, bypassing the proxy.
            let scoped = if name == hyper::header::LINK {
                scope_link_header(&scrubbed_value, scope_uri)
            } else {
                scope_uri(&scrubbed_value)
            };
            match scoped {
                ClientUri::Mapped(mapped) => mapped,
                ClientUri::Unchanged => scrubbed_value,
                ClientUri::Unreachable => {
                    warn!(
                        "Dropped upstream {} for service {} that the route cannot reach",
                        name_str, route.name
                    );
                    continue;
                }
            }
        } else {
            scrubbed_value
        };
        builder = builder.header(name, scrubbed_value);
    }

    if is_streaming {
        // Stream the response body chunk-by-chunk (critical for SSE/streaming APIs).
        // ResponseScrubber performs bounded incremental redaction for both exact
        // vault values and recognized unmanaged credential formats.
        debug!("Streaming response: {}", status);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(32);

        let resp_ct = response_content_type.clone();
        let byte_stream = response.bytes_stream();
        tokio::spawn(async move {
            let mut byte_stream = Box::pin(byte_stream);
            let mut scrub_state = crate::response_scrubber::StreamingScrubState::new();
            let mut upstream_failed = false;

            let mut client_gone = false;

            loop {
                // Watch the client side too: an SDK that gives up must
                // release the upstream socket now, not when the next chunk
                // (or the idle timeout) finally arrives.
                let next = tokio::select! {
                    biased;
                    _ = tx.closed() => {
                        client_gone = true;
                        break;
                    }
                    next = byte_stream.next() => next,
                };
                let Some(chunk_result) = next else {
                    break;
                };
                match chunk_result {
                    Ok(chunk) => {
                        let (scrubbed, scrub_event) = resp_scrubber.scrub_stream_chunk(
                            resp_ct.as_deref(),
                            &mut scrub_state,
                            &chunk,
                        );
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
                            client_gone = true;
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Upstream stream error: {}", e);
                        upstream_failed = true;
                        break;
                    }
                }
            }

            // Dropping the upstream body stream here closes its connection.
            drop(byte_stream);
            if client_gone {
                return;
            }
            if !upstream_failed {
                let (scrubbed, _) = resp_scrubber.finish_stream(resp_ct.as_deref(), scrub_state);
                if !scrubbed.is_empty() {
                    let _ = tx.send(Ok(Frame::data(Bytes::from(scrubbed)))).await;
                }
            } else {
                // Held-back candidate bytes are not flushed for a failed
                // stream: the client is about to see an error anyway.
                // Abort the client body instead of ending it cleanly. A
                // clean end would make a truncated SSE stream (or a cut
                // chunked JSON body) look like a complete response, so SDKs
                // and agents would silently act on partial output.
                let _ = tx
                    .send(Err(std::io::Error::other(
                        "upstream response body ended before completion",
                    )))
                    .await;
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
                Err(_) => {
                    error!("Failed to read response body");
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
            if !reservation.try_reserve(chunk.len()) {
                return Ok(buffer_budget_exhausted_response());
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

        // Set content-length from the final body (may differ after
        // scrubbing). A HEAD response instead keeps the upstream length of
        // the representation, or none when upstream sent none.
        let final_body = Bytes::from(final_body);
        debug!("Response: {} ({} bytes)", status, final_body.len());
        let builder = if method == hyper::Method::HEAD {
            match head_content_length {
                Some(length) => builder.header("content-length", length),
                None => builder,
            }
        } else {
            builder.header("content-length", final_body.len().to_string())
        };
        Ok(builder.body(BoxBody::Left(Full::new(final_body))).unwrap())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BodyReadError {
    Read,
    TooLarge,
    Budget,
}

/// Hop-by-hop headers (RFC 9110 section 7.6.1, plus the de facto
/// `Proxy-Connection` and `Keep-Alive`). They describe one connection and are
/// never forwarded across the proxy in either direction.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Lowercased header names listed in every `Connection` header value. RFC
/// 9110 makes each of them hop-by-hop for this connection.
fn connection_named_headers(headers: &hyper::HeaderMap) -> Vec<String> {
    headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

/// Whether `name` (lowercase, as `HeaderName::as_str` returns it) must stay
/// on this hop.
fn is_hop_by_hop(name: &str, connection_named: &[String]) -> bool {
    HOP_BY_HOP_HEADERS.contains(&name) || connection_named.iter().any(|named| named == name)
}

/// Confine an upstream `Set-Cookie` value to the route it came through.
///
/// All routes are served from the same origin (`127.0.0.1:PORT`), so the
/// upstream's own `Path` and `Domain` describe the upstream host, not the
/// proxy. Left alone, `Path=/` (or the default path of a request to the bare
/// route) makes a client cookie jar send the cookie on requests to every
/// route, and the proxy forwards client cookies, so one upstream's session
/// cookie would reach another upstream (and a hostile upstream could plant
/// cookies on another). Any `Domain` and `Path` attributes are removed and
/// `Path=/<route>` is set, which covers both `/<route>/...` and the
/// `/<route>/_phantom/<token>/...` compatibility base URL. Other attributes
/// are kept in order. Returns `None` when the route name cannot appear in a
/// cookie path, so the cookie is dropped rather than forwarded unscoped.
fn scope_set_cookie_to_route(value: &str, route_name: &str) -> Option<String> {
    if route_name.is_empty()
        || !route_name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b';' && byte != b',')
    {
        return None;
    }
    let mut parts = value.split(';');
    let pair = parts.next().unwrap_or_default().trim();
    if pair.is_empty() {
        return None;
    }
    let mut scoped = vec![pair.to_string()];
    for attribute in parts {
        let attribute = attribute.trim();
        let attribute_name = attribute
            .split_once('=')
            .map_or(attribute, |(name, _)| name)
            .trim();
        if attribute.is_empty()
            || attribute_name.eq_ignore_ascii_case("path")
            || attribute_name.eq_ignore_ascii_case("domain")
        {
            continue;
        }
        scoped.push(attribute.to_string());
    }
    scoped.push(format!("Path=/{route_name}"));
    Some(scoped.join("; "))
}

/// How an upstream URI reference (a `Location`, `Content-Location`, `Link`
/// target or `Link` `anchor`) is presented to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientUri {
    /// Rewritten to name the same upstream resource through the route.
    Mapped(String),
    /// Names another origin (or the upstream outside what the route
    /// reaches, written absolutely): forwarded unchanged, since the client
    /// never resolves it on the proxy's origin.
    Unchanged,
    /// Resolves on the proxy's own origin to a path the route cannot map:
    /// dropped, since a client following it would leave the route prefix
    /// (possibly onto another route) or request the wrong upstream path.
    Unreachable,
}

/// Map an upstream URI reference that stays on the route's own upstream
/// back under the route's local prefix: `/v1/files/abc` (or the same URL
/// written absolutely against the route's upstream origin) becomes
/// `/<route>/v1/files/abc`.
///
/// A relative reference (`next`, `../v2/x`, `?page=2`, `/v1/x`) is relative
/// to the upstream request URL `upstream_request`, not to the client's local
/// URL, so it is resolved there first (RFC 3986 section 5) and the resolved
/// URL is mapped. When the route's upstream base carries a path, only
/// targets under that path are mapped. A path the route would forward to a
/// different upstream path (its SDK version prefix or `//` collapsing) is
/// not mapped either, so following a mapped reference requests exactly the
/// upstream path the upstream named.
///
/// Absolute URLs on other origins (and absolute URLs on the upstream origin
/// that the route cannot reach) are [`ClientUri::Unchanged`]: they never
/// resolve on the proxy, and are never rewritten to point at the route
/// (which would send its credential somewhere else). A relative reference
/// whose resolved URL is on another origin (a network-path reference such
/// as `//host/x`) is likewise unchanged. A relative reference that stays on
/// the upstream origin but cannot be mapped is [`ClientUri::Unreachable`].
fn scope_location_to_route(
    value: &str,
    route: &crate::services::ServiceRoute,
    upstream_request: Option<&reqwest::Url>,
) -> ClientUri {
    let Ok(base) = reqwest::Url::parse(&route.target_base) else {
        return ClientUri::Unchanged;
    };
    let relative = !starts_with_uri_scheme(value);
    let parsed = if relative {
        match upstream_request.map(|request| request.join(value)) {
            Some(Ok(location)) => Ok(location),
            _ => Err(ClientUri::Unreachable),
        }
    } else {
        reqwest::Url::parse(value).map_err(|_| ClientUri::Unchanged)
    };
    let location = match parsed {
        Ok(location) => location,
        Err(outcome) => return outcome,
    };
    // What a reference the route cannot map becomes.
    let unmapped = if relative {
        ClientUri::Unreachable
    } else {
        ClientUri::Unchanged
    };
    if location.scheme() != base.scheme()
        || location.host_str() != base.host_str()
        || location.port_or_known_default() != base.port_or_known_default()
    {
        return ClientUri::Unchanged;
    }
    let route_name = route.name.as_str();
    if route_name.is_empty() || route_name.contains(['/', '?', '#', '\\']) {
        return unmapped;
    }
    let base_path = base.path().trim_end_matches('/');
    let Some(rest_path) = location.path().strip_prefix(base_path) else {
        return unmapped;
    };
    if !(rest_path.is_empty() || rest_path.starts_with('/'))
        || route.upstream_path(rest_path) != rest_path
    {
        return unmapped;
    }
    let mut local = format!("/{route_name}{rest_path}");
    if let Some(query) = location.query() {
        local.push('?');
        local.push_str(query);
    }
    if let Some(fragment) = location.fragment() {
        local.push('#');
        local.push_str(fragment);
    }
    ClientUri::Mapped(local)
}

/// Whether a URI reference starts with a scheme (`scheme:` per RFC 3986
/// section 3.1), so it is an absolute URI rather than a relative reference.
/// Leading C0 controls and spaces are skipped, as URL parsers do.
fn starts_with_uri_scheme(value: &str) -> bool {
    let value = value.trim_start_matches(|ch: char| ch <= ' ');
    let Some(colon) = value.find(':') else {
        return false;
    };
    let scheme = &value[..colon];
    scheme.starts_with(|ch: char| ch.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
}

/// Map an upstream URI reference (a `Location`, `Content-Location`, `Link`
/// target or `Link` `anchor`) for the client. The mapping itself is
/// [`scope_location_to_route`]. When the request came in through the
/// URL-carried auth base `/<route>/_phantom/<proxy token>/`
/// (`path_auth_remainder` is the matched route remainder of that request),
/// the mapped path is written as a reference relative to the request URL,
/// so the client resolves it under its own authenticated base and the proxy
/// never puts the session token (let alone a vault value) in a response
/// header. When no exact relative form exists (the target is the bare route
/// base, or a dot segment would let it climb out of the base), the
/// header-auth form `/<route>/...` is returned instead: the client is then
/// refused with 401, never misrouted.
fn scope_upstream_uri_for_client(
    value: &str,
    route: &crate::services::ServiceRoute,
    upstream_request: Option<&reqwest::Url>,
    path_auth_remainder: Option<&str>,
) -> ClientUri {
    let mapped = match scope_location_to_route(value, route, upstream_request) {
        ClientUri::Mapped(mapped) => mapped,
        other => return other,
    };
    let Some(request_remainder) = path_auth_remainder else {
        return ClientUri::Mapped(mapped);
    };
    let rest = &mapped[1 + route.name.len()..];
    ClientUri::Mapped(relative_to_path_auth_base(rest, request_remainder).unwrap_or(mapped))
}

/// The relative reference that, resolved against
/// `/<route>/_phantom/<token><request_remainder>`, names
/// `/<route>/_phantom/<token><target_rest>`. `None` when that cannot be
/// written without the token.
fn relative_to_path_auth_base(target_rest: &str, request_remainder: &str) -> Option<String> {
    // The request's directory must sit inside the authenticated base.
    let depth = request_remainder.matches('/').count().checked_sub(1)?;
    let tail = target_rest.strip_prefix('/')?;
    let tail_path = tail.split(['?', '#']).next().unwrap_or_default();
    if tail_path.starts_with('/')
        || path_has_dot_segment_or_encoded_separator(tail_path)
        || path_has_path_auth_segment(tail_path)
    {
        return None;
    }
    let prefix = if depth == 0 {
        "./".to_string()
    } else {
        "../".repeat(depth)
    };
    Some(format!("{prefix}{tail}"))
}

/// Index of the first `delimiter` outside a quoted string, and whether the
/// text ends inside an unterminated quoted string.
fn find_unquoted(text: &str, delimiter: char) -> (Option<usize>, bool) {
    let (mut quoted, mut escaped) = (false, false);
    for (index, ch) in text.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
        } else if ch == delimiter {
            return (Some(index), false);
        }
    }
    (None, quoted)
}

/// Rewrite the `anchor` parameter of one link-value's parameter list
/// (`; rel="next"; anchor="..."`) with `map`. Every other parameter, and an
/// anchor `map` leaves unchanged, is kept byte-for-byte; a mapped anchor is
/// written as a quoted string.
fn scope_link_params(params: &str, map: &impl Fn(&str) -> ClientUri) -> ClientUri {
    let mut out = String::with_capacity(params.len());
    let mut rest = params;
    let mut changed = false;
    loop {
        let (end, _) = find_unquoted(rest, ';');
        let param = &rest[..end.unwrap_or(rest.len())];
        let mut written = false;
        if let Some((name, raw)) = param.split_once('=') {
            if name.trim().eq_ignore_ascii_case("anchor") {
                let raw_value = raw.trim();
                let anchor = match raw_value
                    .strip_prefix('"')
                    .and_then(|inner| inner.strip_suffix('"'))
                {
                    Some(inner) => {
                        let mut unescaped = String::with_capacity(inner.len());
                        let mut chars = inner.chars();
                        while let Some(ch) = chars.next() {
                            unescaped.push(if ch == '\\' {
                                chars.next().unwrap_or('\\')
                            } else {
                                ch
                            });
                        }
                        unescaped
                    }
                    None => raw_value.to_string(),
                };
                match map(&anchor) {
                    ClientUri::Mapped(mapped) => {
                        let lead = &raw[..raw.len() - raw.trim_start().len()];
                        let trail = &raw[raw.trim_end().len()..];
                        let quoted = mapped.replace('\\', "\\\\").replace('"', "\\\"");
                        out.push_str(name);
                        out.push('=');
                        out.push_str(lead);
                        out.push('"');
                        out.push_str(&quoted);
                        out.push('"');
                        out.push_str(trail);
                        written = true;
                        changed = true;
                    }
                    ClientUri::Unreachable => return ClientUri::Unreachable,
                    ClientUri::Unchanged => {}
                }
            }
        }
        if !written {
            out.push_str(param);
        }
        match end {
            Some(index) => {
                out.push(';');
                rest = &rest[index + 1..];
            }
            None => break,
        }
    }
    if changed {
        ClientUri::Mapped(out)
    } else {
        ClientUri::Unchanged
    }
}

/// Rewrite each `<target>` and `anchor` parameter of an RFC 8288 `Link`
/// header with `map`, keeping the other parameters (and references `map`
/// leaves unchanged) byte-for-byte. [`ClientUri::Unchanged`] when nothing
/// was rewritten or the header does not parse, so it is forwarded as is;
/// [`ClientUri::Unreachable`] when any reference is, so the header is
/// dropped.
fn scope_link_header(value: &str, map: impl Fn(&str) -> ClientUri) -> ClientUri {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    let mut changed = false;
    loop {
        let trimmed = rest.trim_start();
        out.push_str(&rest[..rest.len() - trimmed.len()]);
        if trimmed.is_empty() {
            break;
        }
        let Some(after_open) = trimmed.strip_prefix('<') else {
            return ClientUri::Unchanged;
        };
        let Some(close) = after_open.find('>') else {
            return ClientUri::Unchanged;
        };
        match map(&after_open[..close]) {
            ClientUri::Mapped(mapped) => {
                out.push('<');
                out.push_str(&mapped);
                out.push('>');
                changed = true;
            }
            ClientUri::Unreachable => return ClientUri::Unreachable,
            ClientUri::Unchanged => out.push_str(&trimmed[..close + 2]),
        }
        let params = &after_open[close + 1..];
        let (split, unterminated) = find_unquoted(params, ',');
        if unterminated {
            return ClientUri::Unchanged;
        }
        let end = split.unwrap_or(params.len());
        match scope_link_params(&params[..end], &map) {
            ClientUri::Mapped(scoped) => {
                out.push_str(&scoped);
                changed = true;
            }
            ClientUri::Unreachable => return ClientUri::Unreachable,
            ClientUri::Unchanged => out.push_str(&params[..end]),
        }
        match split {
            Some(index) => {
                out.push(',');
                rest = &params[index + 1..];
            }
            None => break,
        }
    }
    if changed {
        ClientUri::Mapped(out)
    } else {
        ClientUri::Unchanged
    }
}

/// How many percent-decoding layers of one path segment are inspected. A
/// segment that still changes when decoded after this many layers is refused.
const MAX_PATH_DECODE_LAYERS: usize = 4;

/// Whether a request path carries a `.` or `..` segment (literal or
/// percent-encoded, in any case), a percent-encoded `/` or `\`, or a literal
/// `\`. The outbound URL parser resolves dot segments and treats `\` as a
/// separator for http(s), so any of these could move the forwarded request
/// outside the matched route's base path.
///
/// Every decoding layer is checked, not only the first: reqwest forwards
/// `%252e%252e` verbatim, and an upstream (or an intermediary in front of
/// it) that decodes twice would see `..`. A segment still encoded after
/// [`MAX_PATH_DECODE_LAYERS`] layers is refused as well.
fn path_has_dot_segment_or_encoded_separator(path: &str) -> bool {
    if path.contains('\\') {
        return true;
    }
    path.split('/').any(|segment| {
        let mut layer = segment.as_bytes().to_vec();
        for _ in 0..MAX_PATH_DECODE_LAYERS {
            let decoded = percent_decode_bytes(&layer, false);
            if is_dot_segment_or_has_separator(&decoded) {
                return true;
            }
            if decoded == layer {
                return false;
            }
            layer = decoded;
        }
        true
    })
}

/// Whether one decoded path segment is a dot segment or contains a separator.
fn is_dot_segment_or_has_separator(decoded: &[u8]) -> bool {
    // WHATWG URL parsing removes ASCII tab and newline, so a segment
    // that is only dots once they are removed is treated as a dot
    // segment (conservatively, even when they arrived encoded).
    let significant: Vec<u8> = decoded
        .iter()
        .copied()
        .filter(|byte| !matches!(byte, b'\t' | b'\n' | b'\r'))
        .collect();
    significant == b"."
        || significant == b".."
        || decoded.contains(&b'/')
        || decoded.contains(&b'\\')
}

/// Rebuild the query string for the upstream, dropping `phantom_token` and
/// every route-owned credential parameter. Names are compared ASCII
/// case-insensitively after percent-decoding. Other parameters are forwarded
/// byte-for-byte in their original order; only `&` separates pairs.
fn filter_query(raw: Option<&str>, owned_params: &[&str]) -> String {
    let Some(raw) = raw else {
        return String::new();
    };
    let kept: Vec<&str> = raw
        .split('&')
        .filter(|pair| {
            let name = pair.split_once('=').map_or(*pair, |(name, _)| name);
            let decoded = percent_decode_query_component(name);
            !std::iter::once("phantom_token")
                .chain(owned_params.iter().copied())
                .any(|owned| decoded.eq_ignore_ascii_case(owned.as_bytes()))
        })
        .collect();
    if kept.is_empty() {
        String::new()
    } else {
        format!("?{}", kept.join("&"))
    }
}

/// Whether a header value contains a `phm_` token marker (ASCII
/// case-insensitive). Used only to decide whether to drop the value.
fn carries_phantom_token(value: &[u8]) -> bool {
    value
        .windows(4)
        .any(|window| window.eq_ignore_ascii_case(b"phm_"))
}

/// Decode `%XX` escapes and `+` in a query component. Malformed escapes are
/// kept literally, matching how lenient servers treat them.
fn percent_decode_query_component(component: &str) -> Vec<u8> {
    percent_decode(component, true)
}

/// Decode `%XX` escapes, and `+` as a space when `plus_as_space` is set
/// (query components only; `+` is literal in a path). Malformed escapes are
/// kept literally.
fn percent_decode(component: &str, plus_as_space: bool) -> Vec<u8> {
    percent_decode_bytes(component.as_bytes(), plus_as_space)
}

/// [`percent_decode`] over raw bytes, so already-decoded (possibly
/// non-UTF-8) path segments can be decoded again.
fn percent_decode_bytes(bytes: &[u8], plus_as_space: bool) -> Vec<u8> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                match (
                    bytes.get(i + 1).copied().and_then(hex),
                    bytes.get(i + 2).copied().and_then(hex),
                ) {
                    (Some(high), Some(low)) => {
                        out.push(high << 4 | low);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            b'+' if plus_as_space => out.push(b' '),
            byte => out.push(byte),
        }
        i += 1;
    }
    out
}

/// Extract the username from a client `Authorization: Basic` value when it
/// is a plausible non-secret account identifier. The client's password is
/// never read beyond the separator. Usernames that carry a Phantom token,
/// exceed 128 bytes, or contain characters outside a conservative identifier
/// set are refused and the request is rejected locally.
fn basic_auth_username(value: &hyper::header::HeaderValue) -> Option<String> {
    use base64::Engine as _;
    let value = value.to_str().ok()?.trim();
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?,
    );
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let username = &decoded[..separator];
    if username.is_empty()
        || username.len() > 128
        || !username
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@' | b'+'))
        || carries_phantom_token(username)
    {
        return None;
    }
    // Validated ASCII above.
    Some(String::from_utf8_lossy(username).into_owned())
}

/// The local path segment that introduces URL-carried proxy auth.
const PATH_AUTH_SEGMENT: &str = "_phantom";

/// Split the URL-carried proxy auth pair off a request path. The pair is
/// recognized only at its defined position, directly after the route prefix:
/// `/<route>/_phantom/<proxy token>[/rest]`. A `_phantom` segment anywhere
/// else is left in place, and [`path_has_path_auth_segment`] then refuses the
/// request, so a misplaced pair is never accepted as auth, never silently cut
/// out of the forwarded path, and never forwarded upstream.
fn strip_path_proxy_token(path: &str) -> (String, Option<String>) {
    let mut parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 4
        && parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[2] == PATH_AUTH_SEGMENT
    {
        let token = parts[3].to_string();
        parts.drain(2..=3);
        return (parts.join("/"), Some(token));
    }
    (path.to_string(), None)
}

/// Whether a path (after the defined-position pair was stripped) still has a
/// `_phantom` segment, compared ASCII case-insensitively after
/// percent-decoding.
fn path_has_path_auth_segment(path: &str) -> bool {
    path.split('/').any(|segment| {
        percent_decode(segment, false).eq_ignore_ascii_case(PATH_AUTH_SEGMENT.as_bytes())
    })
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
    async fn test_proxy_query_token_is_stripped_before_the_upstream() {
        // In compatibility mode the proxy token may ride in ?phantom_token=.
        // It authenticates the child to Phantom only: the upstream must get
        // the other parameters but never the token, in any name casing.
        let mock = crate::test_server::MockServer::start().await;
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "test".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
        for name in ["phantom_token", "Phantom_Token"] {
            let resp = client
                .get(format!(
                    "http://127.0.0.1:{}/test/search?q=a&{name}={token}&limit=2",
                    proxy.port()
                ))
                .header("x-phantom-proxy-token", token.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
        }
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/test/search?q=a&phantom_token={token}",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let requests = mock.get_requests();
        assert_eq!(requests.len(), 3);
        for request in &requests {
            assert!(
                !request.path.contains(token.as_str())
                    && !request.path.to_ascii_lowercase().contains("phantom_token"),
                "proxy token reached the upstream: {}",
                request.path
            );
            assert!(request.path.contains("q=a"), "{}", request.path);
            assert_eq!(
                request.headers.get("authorization").unwrap(),
                "Bearer real-secret-value"
            );
        }

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_rejects_a_wrong_query_token_in_compatibility_mode() {
        // Compatibility mode accepts ?phantom_token= only when it matches.
        // A wrong, empty or truncated token must get 401 and never reach the
        // upstream with the injected credential.
        let mock = crate::test_server::MockServer::start().await;
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "test".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
        let truncated = &token[..token.len() - 1];
        for bad in ["wrong-token", "", truncated] {
            for path in ["phantom/health", "test/search"] {
                let resp = client
                    .get(format!(
                        "http://127.0.0.1:{}/{path}?phantom_token={bad}",
                        proxy.port()
                    ))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(resp.status(), 401, "{path} accepted token {bad:?}");
            }
        }
        assert!(mock.get_requests().is_empty(), "upstream was reached");

        proxy.shutdown().await;
        mock.shutdown().await;
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

    /// Start a header-auth proxy with one `test` route to `target_base`.
    async fn failure_probe_proxy(
        target_base: String,
        max_body_size: usize,
    ) -> (ProxyServer, String) {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "test".to_string(),
            target_base,
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        let mut named = HashMap::new();
        named.insert("TEST_API_KEY".to_string(), route_fixture_value());
        let proxy_key = ProxyServer::generate_proxy_token();
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: proxy_key.clone(),
                max_body_size,
                ..ProxyConfig::default()
            },
            registry,
            Interceptor::new_with_named(HashMap::new(), named),
        )
        .await
        .unwrap();
        (proxy, proxy_key)
    }

    /// Runtime-built, credential-free route value.
    fn route_fixture_value() -> String {
        format!("route-fixture-{:x}", std::process::id())
    }

    #[tokio::test]
    async fn upstream_connect_failures_name_a_value_free_reason() {
        let mock = crate::test_server::MockServer::start().await;
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // The DNS case needs a resolver that answers NXDOMAIN for `.invalid`
        // (RFC 6761). Some sandboxes resolve every name or time out, so the
        // proxy reports a different, also value-free, reason. Probe first and
        // skip only that case there; CI resolvers answer NXDOMAIN, so CI
        // still asserts it.
        let nxdomain = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::lookup_host("phantom-unresolvable.invalid:80"),
        )
        .await
        .is_ok_and(|r| r.is_err());
        if !nxdomain {
            eprintln!(
                "skipping dns_resolution_failed case: resolver gave no NXDOMAIN for .invalid"
            );
        }
        let cases = [
            (format!("http://127.0.0.1:{closed}"), "connection_refused"),
            // TLS to a plain-HTTP listener: the handshake cannot complete.
            (
                format!("https://127.0.0.1:{}", mock.port),
                "tls_handshake_failed",
            ),
            (
                "http://phantom-unresolvable.invalid".to_string(),
                "dns_resolution_failed",
            ),
        ];
        for (target_base, reason) in cases {
            if reason == "dns_resolution_failed" && !nxdomain {
                continue;
            }
            let (proxy, proxy_key) = failure_probe_proxy(target_base.clone(), 1024).await;
            let response = reqwest::Client::new()
                .get(format!("http://127.0.0.1:{}/test/v1/models", proxy.port()))
                .header("x-phantom-proxy-token", &proxy_key)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 502, "{target_base}");
            let body = response.text().await.unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["reason"], reason, "{target_base}: {body}");
            assert_eq!(parsed["service"], "test");
            assert_eq!(parsed["error"], "could not connect to upstream service");
            assert!(
                parsed["hint"]
                    .as_str()
                    .is_some_and(|hint| hint.contains(".phantom.toml") || hint.contains("HTTPS")),
                "{body}"
            );
            assert!(!body.contains(&route_fixture_value()), "{body}");
            assert!(!body.contains("127.0.0.1"), "{body}");
            assert!(!body.contains(".invalid"), "{body}");
            proxy.shutdown().await;
        }
        assert!(mock.get_requests().is_empty());
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn proxy_error_bodies_are_labelled_json_and_uncached() {
        let mock = crate::test_server::MockServer::start().await;
        let (proxy, proxy_key) =
            failure_probe_proxy(format!("http://127.0.0.1:{}", mock.port), 16).await;
        let client = reqwest::Client::new();

        let oversized = client
            .post(format!("http://127.0.0.1:{}/test/v1/chat", proxy.port()))
            .header("x-phantom-proxy-token", &proxy_key)
            .body(vec![b'a'; 64])
            .send()
            .await
            .unwrap();
        let unauthorized = client
            .get(format!("http://127.0.0.1:{}/test/v1/models", proxy.port()))
            .send()
            .await
            .unwrap();
        for (response, status) in [(oversized, 413), (unauthorized, 401)] {
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get("content-type").unwrap(),
                "application/json"
            );
            assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
            let body = response.text().await.unwrap();
            serde_json::from_str::<serde_json::Value>(&body).unwrap();
        }
        assert!(mock.get_requests().is_empty());
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn unknown_route_lists_the_configured_route_prefixes() {
        let mock = crate::test_server::MockServer::start().await;
        let (proxy, proxy_key) =
            failure_probe_proxy(format!("http://127.0.0.1:{}", mock.port), 1024).await;

        let response = reqwest::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/openai/v1/models",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", &proxy_key)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 404);
        let parsed: serde_json::Value = response.json().await.unwrap();
        assert_eq!(parsed["routes"], serde_json::json!(["/test"]));
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_never_forwards_its_header_token_upstream() {
        // The local proxy token authenticates the child to Phantom only. It
        // must never reach the upstream, on any header-name casing.
        let mock = crate::test_server::MockServer::start().await;
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "test".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        let mut named = HashMap::new();
        named.insert("TEST_API_KEY".to_string(), "real-secret-value".to_string());
        let interceptor = Interceptor::new_with_named(HashMap::new(), named);
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
        for name in ["x-phantom-proxy-token", "X-Phantom-Proxy-Token"] {
            let resp = client
                .get(format!("http://127.0.0.1:{}/test/headers", proxy.port()))
                .header(name, token.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
        }

        let requests = mock.get_requests();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_eq!(
                request.headers.get("authorization").unwrap(),
                "Bearer real-secret-value"
            );
            assert!(!request.headers.contains_key("x-phantom-proxy-token"));
            assert!(
                request
                    .headers
                    .values()
                    .all(|v| !v.contains(token.as_str())),
                "proxy token reached the upstream: {:?}",
                request.headers
            );
        }

        proxy.shutdown().await;
        mock.shutdown().await;
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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

    #[test]
    fn set_cookie_scoping_replaces_path_and_domain_and_keeps_other_attributes() {
        assert_eq!(
            scope_set_cookie_to_route("a=1; Path=/; Domain=x.test; Secure", "openai").as_deref(),
            Some("a=1; Secure; Path=/openai")
        );
        assert_eq!(
            scope_set_cookie_to_route("a=1", "openai").as_deref(),
            Some("a=1; Path=/openai")
        );
        assert_eq!(
            scope_set_cookie_to_route("a=1;  ;PATH = /x ; Max-Age=60", "r").as_deref(),
            Some("a=1; Max-Age=60; Path=/r")
        );
        // A value that is only attributes has no cookie to scope.
        assert_eq!(scope_set_cookie_to_route("; Path=/", "openai"), None);
        // A route name that cannot sit in a cookie path drops the cookie.
        assert_eq!(scope_set_cookie_to_route("a=1", "bad;name"), None);
        assert_eq!(scope_set_cookie_to_route("a=1", ""), None);
    }

    /// Every route shares the proxy's one origin (`127.0.0.1:PORT`), so a
    /// cookie an upstream sets with `Path=/` (or a `Domain`) would be stored
    /// by a client cookie jar for the whole proxy and replayed to every other
    /// route's upstream. Response cookies must be scoped to their route.
    #[tokio::test]
    async fn upstream_set_cookie_is_scoped_to_its_route_prefix() {
        let mock = crate::test_server::MockServer::start_with_response_headers(&[
            (
                "set-cookie",
                "sid=upstream-session; Path=/; Domain=example.test; Secure; HttpOnly",
            ),
            ("set-cookie", "pref=dark; SameSite=Lax"),
            (
                "set-cookie",
                "scoped=1; path=/v1/files; DOMAIN=.example.test",
            ),
        ])
        .await;
        let fixture = route_fixture_value();

        let mut registry = ServiceRegistry::new();
        for name in ["alpha", "beta"] {
            registry.add_route(ServiceRoute {
                name: name.to_string(),
                target_base: format!("http://127.0.0.1:{}", mock.port),
                secret_key: "TEST_API_KEY".to_string(),
                header: "Authorization".to_string(),
                header_format: "Bearer {secret}".to_string(),
                credential_profile: crate::services::CredentialProfile::Standard,
                sdk_base_path: None,
            });
        }
        let interceptor = Interceptor::new_scoped(
            HashMap::new(),
            HashMap::from([("TEST_API_KEY".to_string(), fixture)]),
        );
        let proxy = ProxyServer::start(ProxyConfig::default(), registry, interceptor)
            .await
            .unwrap();

        let resp = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{}/alpha/v1/models", proxy.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let cookies: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            cookies,
            vec![
                "sid=upstream-session; Secure; HttpOnly; Path=/alpha".to_string(),
                "pref=dark; SameSite=Lax; Path=/alpha".to_string(),
                "scoped=1; Path=/alpha".to_string(),
            ]
        );

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    /// A one-route proxy in front of `mock_port` whose upstream base is
    /// `http://127.0.0.1:<mock_port><base_path>`.
    async fn location_probe_proxy(mock_port: u16, base_path: &str) -> ProxyServer {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "alpha".to_string(),
            target_base: format!("http://127.0.0.1:{mock_port}{base_path}"),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        let interceptor = Interceptor::new_scoped(
            HashMap::new(),
            HashMap::from([("TEST_API_KEY".to_string(), route_fixture_value())]),
        );
        ProxyServer::start(ProxyConfig::default(), registry, interceptor)
            .await
            .unwrap()
    }

    /// Every route shares the proxy's one origin, so an upstream redirect to
    /// an absolute path (`/v1/files/abc`) would be resolved by the client
    /// against `http://127.0.0.1:PORT/` and lose the `/<route>` prefix. A
    /// Location that stays on the route's own upstream is mapped back under
    /// the route prefix; anything that leaves it is passed through unchanged.
    #[tokio::test]
    async fn upstream_location_is_mapped_back_under_its_route_prefix() {
        // (base path, upstream Location, Location the client must see)
        let cases: Vec<(&str, String, String)> = vec![
            ("", "/v1/files/abc".into(), "/alpha/v1/files/abc".into()),
            (
                "",
                "/v1/files?after=f1#top".into(),
                "/alpha/v1/files?after=f1#top".into(),
            ),
            ("", "/".into(), "/alpha/".into()),
            ("/base", "/base/v1/files".into(), "/alpha/v1/files".into()),
            // Relative references are resolved against the upstream request
            // (`/start`) first. Same-origin references outside the route's
            // base path are dropped (see
            // `unreachable_same_origin_references_are_dropped`).
            ("", "next".into(), "/alpha/next".into()),
            ("", "../files/abc".into(), "/alpha/files/abc".into()),
            // Other origins and network-path references are never rewritten
            // to point at the route (which would send its credential there).
            (
                "",
                "//other.example.test/v1".into(),
                "//other.example.test/v1".into(),
            ),
            (
                "",
                "/\\other.example.test/v1".into(),
                "/\\other.example.test/v1".into(),
            ),
            (
                "",
                "https://other.example.test/v1".into(),
                "https://other.example.test/v1".into(),
            ),
            (
                "",
                "https://127.0.0.1/v1".into(),
                "https://127.0.0.1/v1".into(),
            ),
        ];

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for (index, (base_path, upstream, expected)) in cases.iter().enumerate() {
            let mock = crate::test_server::MockServer::start_with_status_and_headers(
                StatusCode::FOUND,
                &[("location", upstream.as_str())],
            )
            .await;
            let proxy = location_probe_proxy(mock.port, base_path).await;
            let resp = client
                .get(format!("http://127.0.0.1:{}/alpha/start", proxy.port()))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FOUND, "case {index}");
            let seen = resp
                .headers()
                .get("location")
                .map(|value| value.to_str().unwrap().to_string());
            assert_eq!(seen.as_deref(), Some(expected.as_str()), "case {index}");
            drop(resp);
            proxy.shutdown().await;
            mock.shutdown().await;
        }
    }

    #[test]
    fn location_scoping_maps_only_the_routes_own_upstream() {
        let route = |target_base: &str, sdk_base_path: Option<&str>| ServiceRoute {
            name: "alpha".to_string(),
            target_base: target_base.to_string(),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: sdk_base_path.map(str::to_string),
        };
        let base = route("https://api.example.test", None);
        let based = route("https://api.example.test/base", None);
        let versioned = route("https://api.example.test", Some("/v1"));
        let mapped = |local: &str| ClientUri::Mapped(local.to_string());
        let (unchanged, unreachable) = (ClientUri::Unchanged, ClientUri::Unreachable);
        let request = |url: &str| reqwest::Url::parse(url).unwrap();
        // The upstream request each route's references are relative to.
        let base_request = request("https://api.example.test/v1/items/abc");
        let based_request = request("https://api.example.test/base/v1/items/abc");
        let versioned_request = request("https://api.example.test/v1/chat");
        let cases: Vec<(&ServiceRoute, &reqwest::Url, &str, ClientUri)> = vec![
            (
                &base,
                &base_request,
                "/v1/files/abc",
                mapped("/alpha/v1/files/abc"),
            ),
            (
                &base,
                &base_request,
                "https://api.example.test/v1/files?x=1#f",
                mapped("/alpha/v1/files?x=1#f"),
            ),
            (
                &base,
                &base_request,
                "https://api.example.test:443/v1",
                mapped("/alpha/v1"),
            ),
            (
                &based,
                &based_request,
                "https://api.example.test/base/v1",
                mapped("/alpha/v1"),
            ),
            (&based, &based_request, "/base?x=1", mapped("/alpha?x=1")),
            (
                &versioned,
                &versioned_request,
                "/v1/files",
                mapped("/alpha/v1/files"),
            ),
            // Relative references resolve against the upstream request.
            (&base, &base_request, "next", mapped("/alpha/v1/items/next")),
            (&base, &base_request, "../v2/x", mapped("/alpha/v1/v2/x")),
            (&base, &base_request, "../../../../x", mapped("/alpha/x")),
            (
                &base,
                &base_request,
                "?p=2",
                mapped("/alpha/v1/items/abc?p=2"),
            ),
            (&base, &base_request, "#f", mapped("/alpha/v1/items/abc#f")),
            (&based, &based_request, "../b", mapped("/alpha/v1/b")),
            (
                &versioned,
                &versioned_request,
                "models",
                mapped("/alpha/v1/models"),
            ),
            // The route would forward these to `/v1/other` and `/x`, or
            // cannot reach them at all: they would resolve on the proxy.
            (
                &versioned,
                &versioned_request,
                "/other",
                unreachable.clone(),
            ),
            (&versioned, &versioned_request, "../x", unreachable.clone()),
            (&based, &based_request, "/other/v1", unreachable.clone()),
            (&based, &based_request, "../../../x", unreachable.clone()),
            (&based, &based_request, "/basement", unreachable.clone()),
            // Absolute URLs and network-path references never resolve on the
            // proxy origin and are never pointed at the route.
            (&base, &base_request, "//x", unchanged.clone()),
            (
                &based,
                &based_request,
                "https://api.example.test/basement",
                unchanged.clone(),
            ),
            (
                &base,
                &base_request,
                "http://api.example.test/v1",
                unchanged.clone(),
            ),
            (
                &base,
                &base_request,
                "https://api.example.test:8443/v1",
                unchanged.clone(),
            ),
            (
                &base,
                &base_request,
                "https://evil.example.test/v1",
                unchanged.clone(),
            ),
            (
                &base,
                &base_request,
                "//evil.example.test/v1",
                unchanged.clone(),
            ),
            (
                &base,
                &base_request,
                "/\\evil.example.test/v1",
                unchanged.clone(),
            ),
            (&base, &base_request, "urn:example:x", unchanged.clone()),
            (&base, &base_request, "https://[bad", unchanged.clone()),
        ];
        for (index, (route, upstream_request, location, expected)) in cases.iter().enumerate() {
            assert_eq!(
                scope_location_to_route(location, route, Some(upstream_request)),
                *expected,
                "case {index}"
            );
        }
        // Without an upstream request URL a relative reference cannot be
        // resolved, so it is never forwarded.
        assert_eq!(scope_location_to_route("next", &base, None), unreachable);
        let mut unnamed = route("https://api.example.test", None);
        unnamed.name = String::new();
        assert_eq!(
            scope_location_to_route("/v1", &unnamed, Some(&base_request)),
            unreachable
        );
    }

    /// Probe one upstream 302 through a one-route proxy (base: the mock's
    /// origin) that requires a session key and accepts the
    /// `/<route>/_phantom/<key>/` base URL. `{origin}` in an upstream header
    /// value is the mock's own origin. Returns the response headers the
    /// client sees and the session key.
    async fn probe_mapped_headers(
        upstream_headers: &[(&str, &str)],
        local_path: impl Fn(&str) -> String,
    ) -> (hyper::HeaderMap, String) {
        let mock = crate::test_server::MockServer::start_with_status_and_headers(
            StatusCode::FOUND,
            upstream_headers,
        )
        .await;
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "alpha".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        let interceptor = Interceptor::new_scoped(
            HashMap::new(),
            HashMap::from([("TEST_API_KEY".to_string(), route_fixture_value())]),
        );
        let session_key = ProxyServer::generate_proxy_token();
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: session_key.clone(),
                allow_query_token_auth: true,
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let path = local_path(&session_key);
        let mut request = client.get(format!("http://127.0.0.1:{}{path}", proxy.port()));
        if !path.contains("/_phantom/") {
            request = request.header("x-phantom-proxy-token", session_key.as_str());
        }
        let resp = request.send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let headers = resp.headers().clone();
        drop(resp);
        proxy.shutdown().await;
        mock.shutdown().await;
        (headers, session_key)
    }

    fn header_text(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
        headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_string())
    }

    /// A client on the `/<route>/_phantom/<key>/` base URL resolves a mapped
    /// redirect against its own request URL, so the Location must keep that
    /// base. It is written relative to the request, so following it lands
    /// on the same authenticated route path and the session key is never
    /// echoed in a response header.
    #[tokio::test]
    async fn path_auth_redirects_keep_the_authenticated_base() {
        // (request remainder, upstream Location, Location the client must see)
        let cases = [
            ("/v1/start", "/v1/files/abc", "../v1/files/abc"),
            (
                "/start",
                "{origin}/v1/files?after=f1",
                "./v1/files?after=f1",
            ),
            ("/", "/v1/files", "./v1/files"),
            ("/a/b/c", "/", "../../"),
        ];
        for (index, (remainder, upstream, expected)) in cases.iter().enumerate() {
            let (headers, session_key) = probe_mapped_headers(&[("location", upstream)], |key| {
                format!("/alpha/_phantom/{key}{remainder}")
            })
            .await;
            let seen = header_text(&headers, "location");
            assert_eq!(seen.as_deref(), Some(*expected), "case {index}");
            // Resolving the mapped Location against the request URL keeps
            // the authenticated base.
            let request_url = reqwest::Url::parse(&format!(
                "http://127.0.0.1/alpha/_phantom/{session_key}{remainder}"
            ))
            .unwrap();
            let followed = request_url.join(seen.as_deref().unwrap()).unwrap();
            let auth_base = format!("/alpha/_phantom/{session_key}/");
            assert!(
                followed.path().starts_with(auth_base.as_str()),
                "case {index}"
            );
            for value in headers.values() {
                let text = value.to_str().unwrap_or_default();
                assert!(!text.contains(session_key.as_str()), "case {index}");
            }
        }
    }

    /// `Content-Location` and `Link` targets naming the route's own upstream
    /// are mapped the way `Location` is, so neither leaks the upstream
    /// origin to the client nor sends it around the proxy. Targets on other
    /// origins, and Link parameters, are left byte-for-byte.
    #[tokio::test]
    async fn content_location_and_link_targets_are_mapped_like_location() {
        let upstream_link = concat!(
            "<{origin}/v1/items?page=2>; rel=\"next\", ",
            "<https://docs.example.test/x>; rel=\"help\"; title=\"a, <b>\", ",
            "</v1/items?page=1>; rel=\"first\""
        );
        let upstream = [
            ("content-location", "{origin}/v1/items/abc"),
            ("link", upstream_link),
        ];
        let (headers, _) = probe_mapped_headers(&upstream, |_| "/alpha/v1/items".into()).await;
        assert_eq!(
            header_text(&headers, "content-location").as_deref(),
            Some("/alpha/v1/items/abc")
        );
        assert_eq!(
            header_text(&headers, "link").as_deref(),
            Some(concat!(
                "</alpha/v1/items?page=2>; rel=\"next\", ",
                "<https://docs.example.test/x>; rel=\"help\"; title=\"a, <b>\", ",
                "</alpha/v1/items?page=1>; rel=\"first\""
            ))
        );

        // Under the path-auth base the same targets come back relative.
        let (headers, _) =
            probe_mapped_headers(&upstream, |key| format!("/alpha/_phantom/{key}/v1/items")).await;
        assert_eq!(
            header_text(&headers, "content-location").as_deref(),
            Some("../v1/items/abc")
        );
        assert_eq!(
            header_text(&headers, "link").as_deref(),
            Some(concat!(
                "<../v1/items?page=2>; rel=\"next\", ",
                "<https://docs.example.test/x>; rel=\"help\"; title=\"a, <b>\", ",
                "<../v1/items?page=1>; rel=\"first\""
            ))
        );
    }

    #[test]
    fn path_auth_relative_references_stay_inside_the_authenticated_base() {
        // (target rest, request remainder, expected reference)
        let cases: [(&str, &str, Option<&str>); 10] = [
            ("/v1/files", "/v1/start", Some("../v1/files")),
            ("/v1/files", "/start", Some("./v1/files")),
            ("/v1/files", "/", Some("./v1/files")),
            ("/", "/a/b/c", Some("../../")),
            ("/a:b/c", "/x", Some("./a:b/c")),
            ("/v1?x=1#f", "/v1/", Some("../v1?x=1#f")),
            // No exact relative form without naming the session key.
            ("", "/v1/start", None),
            ("?x=1", "/v1/start", None),
            ("/v1/files", "", None),
            // Never climb out of the authenticated base.
            ("/v1/../../x", "/v1/start", None),
        ];
        for (index, (rest, remainder, expected)) in cases.iter().enumerate() {
            assert_eq!(
                relative_to_path_auth_base(rest, remainder).as_deref(),
                *expected,
                "case {index}"
            );
        }
        assert_eq!(relative_to_path_auth_base("/_phantom/x", "/v1"), None);
        assert_eq!(relative_to_path_auth_base("//x", "/v1"), None);
    }

    #[test]
    fn path_auth_mapping_falls_back_to_the_header_auth_form() {
        let route = ServiceRoute {
            name: "alpha".to_string(),
            target_base: "https://api.example.test/base".to_string(),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        };
        let upstream_request = reqwest::Url::parse("https://api.example.test/base/v1/b").unwrap();
        let map = |value: &str, remainder: Option<&str>| match scope_upstream_uri_for_client(
            value,
            &route,
            Some(&upstream_request),
            remainder,
        ) {
            ClientUri::Mapped(mapped) => Some(mapped),
            _ => None,
        };
        assert_eq!(map("/base/v1/a", None).as_deref(), Some("/alpha/v1/a"));
        assert_eq!(map("/base/v1/a", Some("/v1/b")).as_deref(), Some("../v1/a"));
        assert_eq!(map("/base/?x=1", Some("/v1/b")).as_deref(), Some("../?x=1"));
        // A relative reference is resolved upstream, then written relative
        // to the client's request again.
        assert_eq!(map("next", Some("/v1/b")).as_deref(), Some("../v1/next"));
        assert_eq!(map("../a", Some("/v1/b")).as_deref(), Some("../a"));
        // The bare route base has no key-free relative form: fail closed to
        // the header-auth path (401 without the header), never misroute.
        assert_eq!(
            map("https://api.example.test/base?x=1", Some("/v1/b")).as_deref(),
            Some("/alpha?x=1")
        );
        assert_eq!(
            map("../../base?x=1", Some("/v1/b")).as_deref(),
            Some("/alpha?x=1")
        );
        assert_eq!(map("https://evil.example.test/v1", Some("/v1/b")), None);
        assert_eq!(
            scope_upstream_uri_for_client(
                "../../x",
                &route,
                Some(&upstream_request),
                Some("/v1/b")
            ),
            ClientUri::Unreachable
        );
    }

    #[test]
    fn link_header_targets_are_rewritten_and_parameters_kept() {
        let map = |target: &str| {
            if target.starts_with("bad:") {
                ClientUri::Unreachable
            } else {
                target
                    .strip_prefix("up:")
                    .map_or(ClientUri::Unchanged, |rest| {
                        ClientUri::Mapped(format!("/r{rest}"))
                    })
            }
        };
        let cases: [(&str, Option<&str>); 12] = [
            ("<up:/a>; rel=next", Some("</r/a>; rel=next")),
            (
                "<up:/a>; rel=\"next\", <other:/b>; rel=help, <up:/c>",
                Some("</r/a>; rel=\"next\", <other:/b>; rel=help, </r/c>"),
            ),
            // Quoted parameters may hold commas, angle brackets and escapes.
            (
                "<up:/a>; title=\"x, <up:/z> \\\" y\", <up:/c>",
                Some("</r/a>; title=\"x, <up:/z> \\\" y\", </r/c>"),
            ),
            ("  <up:/a> ,", Some("  </r/a> ,")),
            // `anchor` (quoted, token, any case) is mapped like a target and
            // always written back quoted; other parameters are kept.
            (
                "<other:/b>; rel=up; anchor=\"up:/x\"; title=\"anchor=up:/y\"",
                Some("<other:/b>; rel=up; anchor=\"/r/x\"; title=\"anchor=up:/y\""),
            ),
            (
                "<up:/a>; ANCHOR = up:/x ; rel=y",
                Some("</r/a>; ANCHOR = \"/r/x\" ; rel=y"),
            ),
            (
                "<other:/b>; anchor=\"up:/q\\\"\"",
                Some("<other:/b>; anchor=\"/r/q\\\"\""),
            ),
            ("<other:/b>; rel=help; anchor=\"other:/c\"", None),
            // Malformed: forwarded unchanged.
            ("up:/a; rel=next", None),
            ("<up:/a>; title=\"open", None),
            // Any unreachable target or anchor drops the whole header.
            ("<up:/a>, <bad:/b>", Some("dropped")),
            ("<up:/a>; anchor=\"bad:/b\"", Some("dropped")),
        ];
        for (index, (value, expected)) in cases.iter().enumerate() {
            let seen = match scope_link_header(value, map) {
                ClientUri::Mapped(mapped) => Some(mapped),
                ClientUri::Unchanged => None,
                ClientUri::Unreachable => Some("dropped".to_string()),
            };
            assert_eq!(seen.as_deref(), *expected, "case {index}");
        }
    }

    /// An upstream relative reference is relative to the upstream request
    /// URL, not to the client's local one, so it is resolved there first and
    /// then mapped like an absolute path. Left alone, `../` could climb out
    /// of the route prefix (onto another route of this same origin) and an
    /// SDK version prefix or base path would make it name the wrong path.
    #[tokio::test]
    async fn relative_upstream_references_are_resolved_before_scoping() {
        // (request remainder, upstream Location, Location the client must see)
        let cases = [
            ("/v1/items/abc", "next", "/alpha/v1/items/next"),
            ("/v1/items/abc", "../v2/x", "/alpha/v1/v2/x"),
            ("/v1/items/abc", "../../../../x", "/alpha/x"),
            ("/v1/items/abc", "?page=2", "/alpha/v1/items/abc?page=2"),
            ("/v1/items/", "./a/../b#f", "/alpha/v1/items/b#f"),
        ];
        for (index, (remainder, upstream, expected)) in cases.iter().enumerate() {
            let (headers, _) =
                probe_mapped_headers(&[("location", upstream)], |_| format!("/alpha{remainder}"))
                    .await;
            assert_eq!(
                header_text(&headers, "location").as_deref(),
                Some(*expected),
                "case {index}"
            );
        }

        // Under the path-auth base the resolved target comes back relative
        // to the request and never climbs out of the authenticated base.
        let path_auth_cases = [
            ("/v1/items/abc", "../v2/x", "../../v1/v2/x"),
            ("/v1/items/abc", "../../../x", "../../x"),
            ("/v1/items/abc", "next", "../../v1/items/next"),
        ];
        for (index, (remainder, upstream, expected)) in path_auth_cases.iter().enumerate() {
            let (headers, session_key) = probe_mapped_headers(&[("location", upstream)], |key| {
                format!("/alpha/_phantom/{key}{remainder}")
            })
            .await;
            let seen = header_text(&headers, "location");
            assert_eq!(seen.as_deref(), Some(*expected), "case {index}");
            let request_url = reqwest::Url::parse(&format!(
                "http://127.0.0.1/alpha/_phantom/{session_key}{remainder}"
            ))
            .unwrap();
            let followed = request_url.join(seen.as_deref().unwrap()).unwrap();
            let auth_base = format!("/alpha/_phantom/{session_key}/");
            assert!(
                followed.path().starts_with(auth_base.as_str()),
                "case {index}"
            );
        }
    }

    /// A same-origin reference the route cannot reach (outside its base
    /// path) would resolve on the proxy's own origin, possibly onto another
    /// route, so it is dropped rather than forwarded.
    #[tokio::test]
    async fn unreachable_same_origin_references_are_dropped() {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        // (upstream Location, Location the client must see)
        let cases: [(&str, Option<&str>); 4] = [
            ("../b", Some("/alpha/b")),
            ("../../b", None),
            ("/basement/x", None),
            // An absolute URL never resolves on the proxy origin: as before,
            // it is forwarded unchanged.
            (
                "https://other.example.test/v1",
                Some("https://other.example.test/v1"),
            ),
        ];
        for (index, (upstream, expected)) in cases.iter().enumerate() {
            let mock = crate::test_server::MockServer::start_with_status_and_headers(
                StatusCode::FOUND,
                &[("location", upstream)],
            )
            .await;
            let proxy = location_probe_proxy(mock.port, "/base").await;
            let resp = client
                .get(format!("http://127.0.0.1:{}/alpha/v1/a", proxy.port()))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FOUND, "case {index}");
            let seen = header_text(resp.headers(), "location");
            assert_eq!(seen.as_deref(), *expected, "case {index}");
            drop(resp);
            proxy.shutdown().await;
            mock.shutdown().await;
        }
    }

    /// A Link `anchor` names the link context; when it is a URI on the
    /// route's own upstream it is mapped exactly like a target, and relative
    /// targets are resolved against the upstream request first.
    #[tokio::test]
    async fn link_anchor_and_relative_targets_are_scoped() {
        let upstream_link = concat!(
            "<{origin}/v1/items/abc/replies>; rel=\"replies\"; anchor=\"{origin}/v1/items/abc\", ",
            "<next>; rel=next; anchor=\"https://docs.example.test/x\", ",
            "<../help>; rel=help; anchor=../items/abc"
        );
        let (headers, _) =
            probe_mapped_headers(&[("link", upstream_link)], |_| "/alpha/v1/items/abc".into())
                .await;
        assert_eq!(
            header_text(&headers, "link").as_deref(),
            Some(concat!(
                "</alpha/v1/items/abc/replies>; rel=\"replies\"; anchor=\"/alpha/v1/items/abc\", ",
                "</alpha/v1/items/next>; rel=next; anchor=\"https://docs.example.test/x\", ",
                "</alpha/v1/help>; rel=help; anchor=\"/alpha/v1/items/abc\""
            ))
        );

        let (headers, session_key) = probe_mapped_headers(&[("link", upstream_link)], |key| {
            format!("/alpha/_phantom/{key}/v1/items/abc")
        })
        .await;
        let seen = header_text(&headers, "link").unwrap_or_default();
        assert!(!seen.contains(session_key.as_str()));
        assert!(!seen.contains("127.0.0.1"));
        assert!(seen.contains("anchor=\"../../v1/items/abc\""));
    }

    /// Send `method target` over a raw socket and return the response head
    /// (status line and headers, lowercased) plus any body bytes that arrive
    /// within a short grace period after it.
    async fn raw_response(port: u16, method: &str, target: &str) -> (String, Vec<u8>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let head = format!(
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(std::time::Duration::from_millis(500), stream.read(&mut buf))
                .await
            {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
            }
        }
        let split = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|at| at + 4)
            .unwrap_or(response.len());
        let head = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
        (head, response[split..].to_vec())
    }

    fn head_header<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(field, _)| field.trim() == name)
            .map(|(_, value)| value.trim())
            .collect()
    }

    /// RFC 9110 section 8.6: a HEAD response's Content-Length describes the
    /// representation a GET would return, a 304's matches the 200 it
    /// replaces, and a 204 never carries one. The proxy must not replace the
    /// upstream length with the length of its own (empty) buffered body.
    #[tokio::test]
    async fn head_response_keeps_upstream_content_length() {
        // The mock's default JSON body, which hyper declares on HEAD too.
        let get_length = r#"{"status":"ok","mock":true}"#.len().to_string();

        let mock = crate::test_server::MockServer::start().await;
        let proxy = location_probe_proxy(mock.port, "").await;
        let (head, body) = raw_response(proxy.port(), "HEAD", "/alpha/v1/files/abc").await;
        assert!(head.starts_with("http/1.1 200"), "HEAD status");
        assert_eq!(
            head_header(&head, "content-length"),
            vec![get_length.as_str()],
            "HEAD response must keep the upstream content-length"
        );
        assert!(body.is_empty(), "HEAD response carried a body");
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn not_modified_response_keeps_upstream_content_length() {
        let get_length = r#"{"status":"ok","mock":true}"#.len().to_string();
        let mock = crate::test_server::MockServer::start_with_status_and_headers(
            StatusCode::NOT_MODIFIED,
            &[("etag", "\"v1\""), ("content-length", get_length.as_str())],
        )
        .await;
        let proxy = location_probe_proxy(mock.port, "").await;
        let (head, body) = raw_response(proxy.port(), "GET", "/alpha/v1/files/abc").await;
        assert!(head.starts_with("http/1.1 304"), "304 status");
        let lengths = head_header(&head, "content-length");
        assert!(
            lengths.is_empty() || lengths == vec![get_length.as_str()],
            "304 response must not claim an empty representation"
        );
        assert!(body.is_empty(), "304 response carried a body");
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn no_content_response_carries_no_content_length() {
        let mock = crate::test_server::MockServer::start_with_status_and_headers(
            StatusCode::NO_CONTENT,
            &[],
        )
        .await;
        let proxy = location_probe_proxy(mock.port, "").await;
        let (head, body) = raw_response(proxy.port(), "DELETE", "/alpha/v1/files/abc").await;
        assert!(head.starts_with("http/1.1 204"), "204 status");
        assert!(
            head_header(&head, "content-length").is_empty(),
            "204 response must not carry content-length"
        );
        assert!(body.is_empty(), "204 response carried a body");
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    /// A double-encoded `_phantom` segment (`%255fphantom`) decodes once to
    /// `%5fphantom`, never to `_phantom`, at a single-decoding upstream. It is
    /// forwarded byte-for-byte: the proxy neither strips it as path auth nor
    /// decodes it into a different path.
    #[tokio::test]
    async fn double_encoded_path_auth_segment_is_forwarded_verbatim() {
        let mock = crate::test_server::MockServer::start().await;
        let proxy = location_probe_proxy(mock.port, "").await;
        let (head, _) = raw_response(proxy.port(), "GET", "/alpha/v1/%255fphantom/x").await;
        assert!(head.starts_with("http/1.1 200"), "status");
        let paths: Vec<String> = mock.get_requests().into_iter().map(|r| r.path).collect();
        assert_eq!(paths, vec!["/v1/%255fphantom/x".to_string()]);
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
    async fn sdk_base_url_with_appended_version_reaches_upstream_without_double_slash() {
        // `phantom exec` exports a slash-terminated base URL with the session
        // token in the path; callers appending `/v1/...` produce `T//v1/...`.
        let mock = crate::test_server::MockServer::start().await;
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "testapi".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "TEST_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        let interceptor = Interceptor::new_scoped(
            HashMap::new(),
            HashMap::from([("TEST_API_KEY".to_string(), "sk-route-owned".to_string())]),
        );
        let token = "session-token-for-path-auth";
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: token.to_string(),
                allow_query_token_auth: true,
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap();

        let base = format!(
            "http://127.0.0.1:{}/testapi/_phantom/{token}/",
            proxy.port()
        );
        let resp = reqwest::Client::new()
            .get(format!("{base}/v1/models"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/models");
        assert_eq!(
            requests[0].headers.get("authorization"),
            Some(&"Bearer sk-route-owned".to_string())
        );

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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
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

    /// One-connection upstream that replays `script` as raw HTTP/1.1 bytes
    /// (each part after its delay) and then closes the socket. Lets tests
    /// model slow streams and mid-body disconnects the hyper mock cannot.
    async fn scripted_upstream(script: Vec<(u64, &'static str)>) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                head.extend_from_slice(&buf[..n]);
            }
            for (delay_ms, part) in script {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                if stream.write_all(part.as_bytes()).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;
            }
        });
        port
    }

    async fn proxy_to(upstream_port: u16, upstream_timeout_secs: u64) -> ProxyServer {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "anthropic".to_string(),
            target_base: format!("http://127.0.0.1:{upstream_port}"),
            secret_key: "ANTHROPIC_API_KEY".to_string(),
            header: "x-api-key".to_string(),
            header_format: "{secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        // Mirror `phantom exec`: the session token map and the named map
        // carry the same value (the response scrubber reads the former).
        let interceptor = Interceptor::new_scoped(
            HashMap::from([(
                "phm_session_token_for_stream_tests".to_string(),
                (
                    "ANTHROPIC_API_KEY".to_string(),
                    "route-owned-anthropic-value".to_string(),
                ),
            )]),
            HashMap::from([(
                "ANTHROPIC_API_KEY".to_string(),
                "route-owned-anthropic-value".to_string(),
            )]),
        );
        ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: "stream-test-token".to_string(),
                upstream_timeout_secs,
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap()
    }

    const SSE_HEAD: &str =
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";

    #[tokio::test]
    async fn sse_stream_longer_than_upstream_timeout_is_not_cut_off() {
        // Claude Code / OpenAI SDK streams routinely run for minutes. The
        // upstream timeout must bound idle gaps, not the whole response.
        let upstream = scripted_upstream(vec![
            (0, SSE_HEAD),
            (0, "f\r\ndata: event-1\n\n\r\n"),
            (600, "f\r\ndata: event-2\n\n\r\n"),
            (600, "f\r\ndata: event-3\n\n\r\n"),
            (600, "f\r\ndata: event-4\n\n\r\n"),
            (0, "0\r\n\r\n"),
        ])
        .await;
        let proxy = proxy_to(upstream, 1).await;
        let resp = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/anthropic/v1/messages?beta=true",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", "stream-test-token")
            .body(r#"{"stream":true}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.expect("complete stream");
        for n in 1..=4 {
            assert!(body.contains(&format!("data: event-{n}\n\n")), "{body:?}");
        }
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn slow_buffered_body_longer_than_upstream_timeout_is_delivered() {
        let upstream = scripted_upstream(vec![
            (
                0,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 12\r\n\r\n",
            ),
            (0, "{\"ok\":"),
            (700, "true"),
            (700, "}\n"),
        ])
        .await;
        let proxy = proxy_to(upstream, 1).await;
        let resp = reqwest::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/anthropic/v1/models",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", "stream-test-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "{\"ok\":true}\n");
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn stalled_upstream_still_times_out() {
        let upstream = scripted_upstream(vec![(2_500, SSE_HEAD)]).await;
        let proxy = proxy_to(upstream, 1).await;
        let resp = reqwest::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/anthropic/v1/models",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", "stream-test-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 502);
        assert!(resp.text().await.unwrap().contains("timed out"));
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn upstream_disconnect_mid_stream_is_not_reported_as_complete() {
        // A cut SSE stream must surface as a transport error so the SDK
        // retries or fails, instead of a clean but truncated response.
        let upstream = scripted_upstream(vec![
            (0, SSE_HEAD),
            (0, "15\r\ndata: partial-delta\n\n\r\n"),
            (50, "40\r\ndata: this chunk never fin"),
        ])
        .await;
        let proxy = proxy_to(upstream, 5).await;
        let resp = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/anthropic/v1/messages",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", "stream-test-token")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(
            resp.bytes().await.is_err(),
            "truncated upstream stream was delivered as a complete body"
        );
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn uncredentialed_route_error_names_service_and_fix() {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "anthropic".to_string(),
            target_base: "http://127.0.0.1:9".to_string(),
            secret_key: "ANTHROPIC_API_KEY".to_string(),
            header: "x-api-key".to_string(),
            header_format: "{secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: "t".to_string(),
                ..ProxyConfig::default()
            },
            registry,
            Interceptor::new_scoped(HashMap::new(), HashMap::new()),
        )
        .await
        .unwrap();
        let resp = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/anthropic/v1/messages",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", "t")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
        let body: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["error"], "route credential unavailable");
        assert_eq!(body["source"], "phantom-proxy");
        assert_eq!(body["service"], "anthropic");
        assert_eq!(body["secret_key"], "ANTHROPIC_API_KEY");
        proxy.shutdown().await;
    }

    /// One-connection upstream that writes `first`, then holds the response
    /// open until the returned gate fires (writing `rest` part by part) or
    /// until the proxy closes the connection, which `closed` reports.
    async fn gated_upstream(
        first: &'static str,
        rest: Vec<&'static str>,
    ) -> (
        u16,
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                head.extend_from_slice(&buf[..n]);
            }
            stream.write_all(first.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            tokio::select! {
                gate = gate_rx => {
                    if gate.is_ok() {
                        for part in rest {
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                            stream.write_all(part.as_bytes()).await.unwrap();
                            stream.flush().await.unwrap();
                        }
                    }
                }
                _ = async {
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                } => {
                    let _ = closed_tx.send(());
                }
            }
        });
        (port, gate_tx, closed_rx)
    }

    #[tokio::test]
    async fn unframed_ndjson_stream_is_streamed_and_scrubbed_across_chunks() {
        // No content-length and no chunked framing: a close-delimited NDJSON
        // stream. The first line must reach the client while the upstream is
        // still holding the rest back (no timing assumptions), and a managed
        // value split across writes must still be redacted.
        let (upstream, gate, _closed) = gated_upstream(
            "HTTP/1.1 200 OK\r\ncontent-type: application/x-ndjson\r\nconnection: close\r\n\r\n{\"delta\":\"first\"}\n",
            vec!["{\"leak\":\"route-owned-", "anthropic-value\"}\n"],
        )
        .await;
        let proxy = proxy_to(upstream, 30).await;
        let mut resp = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/anthropic/v1/stream",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", "stream-test-token")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let mut body = Vec::new();
        while !body.ends_with(b"\n") {
            let chunk = tokio::time::timeout(std::time::Duration::from_secs(10), resp.chunk())
                .await
                .expect("first NDJSON line was held until the upstream finished")
                .unwrap()
                .expect("first line");
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"{\"delta\":\"first\"}\n");
        gate.send(()).unwrap();
        while let Some(chunk) = resp.chunk().await.unwrap() {
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(body).unwrap();
        assert!(!text.contains("route-owned-anthropic-value"), "{text}");
        assert!(!text.contains("anthropic-value"), "{text}");
        assert!(text.contains("[REDACTED"), "{text}");
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn client_disconnect_releases_an_idle_upstream_stream_promptly() {
        // With a 600 s idle timeout the forwarding task must not wait for the
        // next upstream byte to notice that the client went away.
        let (upstream, _gate, closed) = gated_upstream(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\nf\r\ndata: event-1\n\n\r\n",
            Vec::new(),
        )
        .await;
        let proxy = proxy_to(upstream, 600).await;
        let mut resp = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/anthropic/v1/messages",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", "stream-test-token")
            .body("{}")
            .send()
            .await
            .unwrap();
        let first = resp.chunk().await.unwrap().expect("first event");
        assert_eq!(&first[..], b"data: event-1\n\n");
        drop(resp);
        tokio::time::timeout(std::time::Duration::from_secs(10), closed)
            .await
            .expect("upstream connection stayed open after the client disconnected")
            .expect("upstream observed close");
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn aggregate_buffer_budget_bounds_request_bodies() {
        let mock = crate::test_server::MockServer::start().await;
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "anthropic".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "ANTHROPIC_API_KEY".to_string(),
            header: "x-api-key".to_string(),
            header_format: "{secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: "t".to_string(),
                max_body_size: 4096,
                max_buffered_bytes: 1024,
                ..ProxyConfig::default()
            },
            registry,
            Interceptor::new_scoped(
                HashMap::new(),
                HashMap::from([("ANTHROPIC_API_KEY".to_string(), "v".to_string())]),
            ),
        )
        .await
        .unwrap();
        let client = reqwest::Client::new();
        let url = format!("http://127.0.0.1:{}/anthropic/v1/messages", proxy.port());

        // Within the per-body cap but over the shared budget: rejected.
        let over = client
            .post(&url)
            .header("x-phantom-proxy-token", "t")
            .body(vec![b'a'; 2048])
            .send()
            .await
            .unwrap();
        assert_eq!(over.status(), 503);
        assert!(over.headers().contains_key("retry-after"));
        let body: serde_json::Value = serde_json::from_str(&over.text().await.unwrap()).unwrap();
        assert_eq!(body["source"], "phantom-proxy");
        assert!(mock.get_requests().is_empty());

        // Budget is returned when a request finishes, so repeated in-budget
        // requests (body plus buffered response) keep succeeding.
        for _ in 0..3 {
            let ok = client
                .post(&url)
                .header("x-phantom-proxy-token", "t")
                .body(vec![b'a'; 512])
                .send()
                .await
                .unwrap();
            assert_eq!(ok.status(), 200);
        }
        assert_eq!(mock.get_requests().len(), 3);
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[test]
    fn buffer_reservation_releases_bytes_on_drop() {
        let budget = Arc::new(Semaphore::new(100));
        let mut first = BufferReservation::new(budget.clone());
        assert!(first.try_reserve(60));
        assert!(first.try_reserve(30));
        let mut second = BufferReservation::new(budget.clone());
        assert!(!second.try_reserve(20));
        drop(first);
        assert_eq!(budget.available_permits(), 100);
        assert!(second.try_reserve(100));
    }

    #[tokio::test]
    async fn proxy_error_bodies_escape_route_names() {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "r".to_string(),
            target_base: "http://127.0.0.1:9".to_string(),
            secret_key: "KEY\"\\".to_string(),
            header: "x-api-key".to_string(),
            header_format: "{secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: "t".to_string(),
                ..ProxyConfig::default()
            },
            registry,
            Interceptor::new_scoped(HashMap::new(), HashMap::new()),
        )
        .await
        .unwrap();
        let resp = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{}/r/v1", proxy.port()))
            .header("x-phantom-proxy-token", "t")
            .send()
            .await
            .unwrap();
        let text = resp.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&text).expect(&text);
        assert_eq!(body["secret_key"], "KEY\"\\", "{text}");
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn request_bodies_up_to_32_mib_are_forwarded_and_larger_ones_rejected() {
        assert_eq!(ProxyConfig::default().max_body_size, 32 * 1024 * 1024);
        let mock = crate::test_server::MockServer::start().await;
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "anthropic".to_string(),
            target_base: format!("http://127.0.0.1:{}", mock.port),
            secret_key: "ANTHROPIC_API_KEY".to_string(),
            header: "x-api-key".to_string(),
            header_format: "{secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
        let proxy = ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: "t".to_string(),
                ..ProxyConfig::default()
            },
            registry,
            Interceptor::new_scoped(
                HashMap::new(),
                HashMap::from([("ANTHROPIC_API_KEY".to_string(), "v".to_string())]),
            ),
        )
        .await
        .unwrap();
        let client = reqwest::Client::new();
        let url = format!("http://127.0.0.1:{}/anthropic/v1/messages", proxy.port());

        // 12 MiB: an image-heavy agent turn that the old 10 MiB cap rejected.
        let ok = client
            .post(&url)
            .header("x-phantom-proxy-token", "t")
            .body(vec![b'a'; 12 * 1024 * 1024])
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
        assert_eq!(mock.get_requests()[0].body.len(), 12 * 1024 * 1024);

        let too_big = client
            .post(&url)
            .header("x-phantom-proxy-token", "t")
            .body(vec![b'a'; 32 * 1024 * 1024 + 1])
            .send()
            .await;
        // The proxy may answer 413 before the client finishes writing.
        if let Ok(resp) = too_big {
            assert_eq!(resp.status(), 413);
        }
        assert_eq!(
            mock.get_requests().len(),
            1,
            "oversized body reached upstream"
        );
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    /// Start a proxy with one route whose vault value is `secret`.
    async fn single_route_proxy(
        upstream_port: u16,
        header: &str,
        header_format: &str,
        credential_profile: crate::services::CredentialProfile,
        secret: &str,
    ) -> ProxyServer {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "svc".to_string(),
            target_base: format!("http://127.0.0.1:{upstream_port}"),
            secret_key: "SVC_SECRET".to_string(),
            header: header.to_string(),
            header_format: header_format.to_string(),
            credential_profile,
            sdk_base_path: None,
        });
        let interceptor = Interceptor::new_scoped(
            HashMap::new(),
            HashMap::from([("SVC_SECRET".to_string(), secret.to_string())]),
        );
        ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: String::new(),
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap()
    }

    async fn basic_route_proxy(upstream_port: u16, secret: &str) -> ProxyServer {
        single_route_proxy(
            upstream_port,
            "Authorization",
            "Basic {secret}",
            crate::services::CredentialProfile::BasicPassword,
            secret,
        )
        .await
    }

    async fn google_route_proxy(upstream_port: u16, secret: &str) -> ProxyServer {
        single_route_proxy(
            upstream_port,
            "x-goog-api-key",
            "{secret}",
            crate::services::CredentialProfile::GoogleApiKey,
            secret,
        )
        .await
    }

    /// Random lowercase hex from the OS CSPRNG, so no credential literal
    /// flows into a test request.
    fn random_hex(bytes: usize) -> String {
        use rand::RngCore;
        let mut buf = vec![0u8; bytes];
        rand::thread_rng().fill_bytes(&mut buf);
        hex::encode(buf)
    }

    fn basic(user: &str, password: &str) -> String {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    }

    fn session_token() -> String {
        format!("phm_{}", "ab12".repeat(16))
    }

    #[tokio::test]
    async fn basic_route_keeps_client_username_and_injects_vault_password() {
        let mock = crate::test_server::MockServer::start().await;
        let secret_value = random_hex(16);
        let secret = secret_value.as_str();
        let proxy = basic_route_proxy(mock.port, secret).await;
        let path_owner = format!("AC{}", random_hex(16));
        let token = session_token();

        let resp = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/svc/2010-04-01/Accounts/{path_owner}/Messages.json",
                proxy.port()
            ))
            .header("Authorization", basic(&path_owner, &token))
            .body("To=x&From=y&Body=hi")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let requests = mock.get_requests();
        let auth = requests[0].headers.get("authorization").unwrap();
        assert_eq!(auth, &basic(&path_owner, secret));
        assert!(!auth.contains("phm_"));
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn basic_route_uses_first_authorization_and_forwards_neither() {
        let mock = crate::test_server::MockServer::start().await;
        let secret_value = random_hex(16);
        let secret = secret_value.as_str();
        let proxy = basic_route_proxy(mock.port, secret).await;
        let token = session_token();
        let first_user = format!("first_{}", random_hex(4));
        let second_user = format!("second_{}", random_hex(4));

        let resp = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{}/svc/ping", proxy.port()))
            .header("Authorization", basic(&first_user, &token))
            .header(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&basic(&second_user, &token)).unwrap(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let recorded = &mock.get_requests()[0];
        assert_eq!(
            recorded.headers.get("authorization").unwrap(),
            &basic(&first_user, secret)
        );
        assert!(recorded
            .headers
            .values()
            .all(|value| !value.contains("phm_") && !value.contains(&basic(&second_user, &token))));
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    /// Basic-route proxy as `phantom exec` builds it: the vault value is in
    /// both the session-token map (response scrubbing) and the named map
    /// (header injection).
    async fn basic_route_session_proxy(upstream_port: u16, secret: &str) -> ProxyServer {
        let mut registry = ServiceRegistry::new();
        registry.add_route(crate::services::ServiceRoute {
            name: "svc".to_string(),
            target_base: format!("http://127.0.0.1:{upstream_port}"),
            secret_key: "SVC_SECRET".to_string(),
            header: "Authorization".to_string(),
            header_format: "Basic {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::BasicPassword,
            sdk_base_path: None,
        });
        let interceptor = Interceptor::new_scoped(
            HashMap::from([(
                session_token(),
                ("SVC_SECRET".to_string(), secret.to_string()),
            )]),
            HashMap::from([("SVC_SECRET".to_string(), secret.to_string())]),
        );
        ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: String::new(),
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap()
    }

    /// An upstream that reflects the injected `Authorization: Basic` value
    /// hands the child `base64(username:vault_value)`, which decodes straight
    /// to the vault value. The encoded pair must be redacted from response
    /// headers and from buffered and streamed bodies, like a raw echo.
    #[tokio::test]
    async fn basic_route_echo_of_injected_pair_never_reaches_the_client() {
        for content_type in ["application/json", "text/event-stream"] {
            let mock =
                crate::test_server::MockServer::start_echoing("authorization", content_type).await;
            let secret_value = random_hex(16);
            let proxy = basic_route_session_proxy(mock.port, &secret_value).await;
            let path_owner = format!("AC{}", random_hex(16));

            let resp = reqwest::Client::new()
                .get(format!(
                    "http://127.0.0.1:{}/svc/2010-04-01/Accounts/{path_owner}.json",
                    proxy.port()
                ))
                .header("Authorization", basic(&path_owner, &session_token()))
                .send()
                .await
                .unwrap();
            let echoed_header = resp
                .headers()
                .get("x-echo")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = resp.text().await.unwrap();

            let injected = basic(&path_owner, &secret_value);
            let recorded = mock.get_requests();
            assert!(
                recorded[0].headers.get("authorization") == Some(&injected),
                "upstream must receive the injected Basic credential"
            );

            let encoded = injected.strip_prefix("Basic ").unwrap();
            // Base64 characters from here on encode only vault-value bytes
            // (the path owner is 34 bytes, plus ':' makes 35; 36 / 3 * 4 = 48).
            let secret_part = &encoded[48..];
            for (place, text) in [("header", &echoed_header), ("body", &body)] {
                let leaked_whole = text.contains(encoded);
                let leaked_run = secret_part
                    .as_bytes()
                    .windows(12)
                    .any(|window| text.as_bytes().windows(12).any(|seen| seen == window));
                assert!(
                    !leaked_whole && !leaked_run,
                    "encoded Basic credential echoed in the {place} ({content_type}) reached the client"
                );
                assert!(
                    text.contains("[REDACTED:"),
                    "echo in the {place} ({content_type}) was not marked redacted"
                );
            }

            proxy.shutdown().await;
            mock.shutdown().await;
        }
    }

    #[tokio::test]
    async fn basic_route_rejects_unusable_client_usernames_locally() {
        let mock = crate::test_server::MockServer::start().await;
        let secret_value = random_hex(16);
        let secret = secret_value.as_str();
        let proxy = basic_route_proxy(mock.port, secret).await;
        let token = session_token();
        let client = reqwest::Client::new();
        let url = format!("http://127.0.0.1:{}/svc/ping", proxy.port());

        // A phantom token as username, a username with a non-identifier
        // character, a non-Basic scheme, and no header at all are rejected
        // by the proxy; nothing reaches the upstream.
        let client_password = random_hex(8);
        let bad_shape_user = format!("acct/../{}", random_hex(2));
        for header in [
            Some(basic(&token, &client_password)),
            Some(basic(&bad_shape_user, &client_password)),
            Some(format!("Bearer {token}")),
            None,
        ] {
            let mut request = client.get(&url);
            if let Some(header) = header {
                request = request.header("Authorization", header);
            }
            let resp = request.send().await.unwrap();
            assert_eq!(resp.status(), 400);
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(body["source"], "phantom-proxy");
            assert_eq!(body["service"], "svc");
            let text = body.to_string();
            assert!(!text.contains(secret));
            assert!(!text.contains("phm_"));
            assert!(text.contains("Authorization: Basic base64(<ACCOUNT_SID>:<anything>)"));
        }
        assert!(mock.get_requests().is_empty());
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn google_api_key_route_owns_query_key_and_phantom_authorization() {
        let mock = crate::test_server::MockServer::start().await;
        let secret_value = random_hex(16);
        let secret = secret_value.as_str();
        let proxy = google_route_proxy(mock.port, secret).await;
        let token = session_token();

        let resp = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{}/svc/v1beta/models/m:streamGenerateContent?alt=sse&key={token}&KEY={token}&k%65y={token}&api_key={token}&keyword=ok&a=1;key=kept",
                proxy.port()
            ))
            .header("Authorization", format!("Bearer {}", token.to_uppercase()))
            .header("x-goog-api-key", &token)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let recorded = &mock.get_requests()[0];
        assert_eq!(
            recorded.path,
            "/v1beta/models/m:streamGenerateContent?alt=sse&keyword=ok&a=1;key=kept"
        );
        assert_eq!(recorded.headers.get("x-goog-api-key").unwrap(), secret);
        assert!(!recorded.headers.contains_key("authorization"));
        assert!(recorded
            .headers
            .values()
            .all(|value| !value.to_ascii_lowercase().contains("phm_")));
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn google_api_key_route_forwards_clients_own_oauth_bearer() {
        let mock = crate::test_server::MockServer::start().await;
        let proxy = google_route_proxy(mock.port, &random_hex(16)).await;
        let oauth = format!("Bearer {}", random_hex(16));

        let resp = reqwest::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/svc/v1beta/models",
                proxy.port()
            ))
            .header("Authorization", &oauth)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            mock.get_requests()[0].headers.get("authorization"),
            Some(&oauth)
        );
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn standard_routes_keep_key_query_params_and_ignore_basic_shape() {
        let mock = crate::test_server::MockServer::start().await;
        // Same header shape as the Twilio route, but no trusted profile: the
        // plain template applies and `key=` is forwarded.
        let secret_value = random_hex(16);
        let secret = secret_value.as_str();
        let proxy = single_route_proxy(
            mock.port,
            "Authorization",
            "Basic {secret}",
            crate::services::CredentialProfile::Standard,
            secret,
        )
        .await;
        let resp = reqwest::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/svc/v1/items?key=sort-field",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let recorded = &mock.get_requests()[0];
        assert_eq!(recorded.path, "/v1/items?key=sort-field");
        assert_eq!(
            recorded.headers.get("authorization").unwrap(),
            &format!("Basic {secret}")
        );
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn cloudflare_sdk_and_wrangler_base_urls_reach_client_v4() {
        // The trusted built-in route, pointed at the mock upstream.
        let services = std::collections::BTreeMap::from([(
            "cloudflare".to_string(),
            phantom_core::config::PhantomConfig::trusted_builtin_proxy_service("cloudflare")
                .unwrap(),
        )]);
        let mut route = ServiceRegistry::from_config(&services)
            .match_route("/cloudflare")
            .unwrap()
            .0
            .clone();
        let mock = crate::test_server::MockServer::start().await;
        route.target_base = format!("http://127.0.0.1:{}", mock.port);
        let mut registry = ServiceRegistry::new();
        registry.add_route(route);

        let secret_value = random_hex(20);
        let interceptor = Interceptor::new_scoped(
            HashMap::new(),
            HashMap::from([("CLOUDFLARE_API_TOKEN".to_string(), secret_value.clone())]),
        );
        let token = random_hex(16);
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

        // The value `phantom exec` exports as CLOUDFLARE_BASE_URL and
        // CLOUDFLARE_API_BASE_URL.
        let base = format!(
            "http://127.0.0.1:{}/cloudflare/_phantom/{token}/",
            proxy.port()
        );
        let client = reqwest::Client::new();
        // Wrangler concatenates `${base}${resource}`; the Stainless SDKs
        // join without a doubled slash; explicit versioned paths pass as-is.
        for (requested, expected) in [
            ("/user/tokens/verify", "/client/v4/user/tokens/verify"),
            (
                "accounts/abc/workers/scripts",
                "/client/v4/accounts/abc/workers/scripts",
            ),
            ("client/v4/zones?per_page=5", "/client/v4/zones?per_page=5"),
        ] {
            let resp = client
                .get(format!("{base}{requested}"))
                .header("authorization", format!("Bearer {}", session_token()))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "{requested}");
            let recorded = mock.get_requests().pop().unwrap();
            assert_eq!(recorded.path, expected);
            assert_eq!(
                recorded.headers.get("authorization").unwrap(),
                &format!("Bearer {secret_value}")
            );
        }
        assert_eq!(mock.get_requests().len(), 3);
        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[test]
    fn filter_query_drops_owned_params_after_decoding() {
        assert_eq!(filter_query(None, &["key"]), "");
        assert_eq!(filter_query(Some("a=1&b=2"), &[]), "?a=1&b=2");
        assert_eq!(filter_query(Some("phantom_token=t&a=1"), &[]), "?a=1");
        assert_eq!(
            filter_query(Some("Phantom_Token=t&phantom%5Ftoken=u&a=1"), &[]),
            "?a=1"
        );
        assert_eq!(
            filter_query(
                Some("key=1&Key=2&%6B%45y=3&key&a=key&api_key=4"),
                &["key", "api_key"]
            ),
            "?a=key"
        );
        assert_eq!(filter_query(Some("key=1"), &["key"]), "");
        assert_eq!(filter_query(Some("a=1;key=2"), &["key"]), "?a=1;key=2");
        assert_eq!(filter_query(Some("%zz=1&k%2=2"), &["key"]), "?%zz=1&k%2=2");
    }

    #[test]
    fn phantom_token_detection_is_case_insensitive() {
        assert!(carries_phantom_token(b"Bearer phm_abc"));
        assert!(carries_phantom_token(b"Bearer PHM_ABC"));
        assert!(!carries_phantom_token(b"Bearer ya29.token"));
    }

    #[test]
    fn basic_auth_username_parsing() {
        use hyper::header::HeaderValue;
        let parse = |value: &str| basic_auth_username(&HeaderValue::from_str(value).unwrap());
        let pw = random_hex(8);
        let user = format!("acct_{}", random_hex(4));
        assert_eq!(parse(&basic(&user, &pw)).as_deref(), Some(user.as_str()));
        let empty_password = String::new();
        assert_eq!(
            parse(&basic(&user, &empty_password)).as_deref(),
            Some(user.as_str())
        );
        let email_user = format!("{}@example.com", random_hex(4));
        assert_eq!(
            parse(&basic(&email_user, &format!("{pw}:{pw}"))).as_deref(),
            Some(email_user.as_str())
        );
        assert_eq!(parse(&basic("", &pw)), None);
        assert_eq!(parse(&basic(&"a".repeat(129), &pw)), None);
        assert_eq!(parse(&basic(&session_token(), &pw)), None);
        assert_eq!(
            parse(&basic(&format!("x-PHM_{}", random_hex(2)), &pw)),
            None
        );
        assert_eq!(parse(&basic(&format!("a {}", random_hex(2)), &pw)), None);
        assert_eq!(parse("Basic not-base64!"), None);
        assert_eq!(parse("Bearer abc"), None);
        use base64::Engine as _;
        let no_colon = base64::engine::general_purpose::STANDARD.encode("nocolon");
        assert_eq!(parse(&format!("Basic {no_colon}")), None);
    }

    /// Send one raw HTTP/1.1 request so the request target reaches the proxy
    /// exactly as written (reqwest/url would normalize dot segments first).
    /// Returns the response status code.
    async fn send_raw_request(port: u16, target: &str, extra_headers: &[(&str, &str)]) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut head = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n");
        for (name, value) in extra_headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if !extra_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("connection"))
        {
            head.push_str("Connection: close\r\n");
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
                .await
            {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        let text = String::from_utf8_lossy(&response);
        text.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    async fn traversal_probe_proxy(mock_port: u16) -> ProxyServer {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "openai".to_string(),
            target_base: format!("http://127.0.0.1:{mock_port}"),
            secret_key: "OPENAI_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: Some("/v1".to_string()),
        });
        let fixture = format!("{}{}", "sk", "-traversal-fixture-0123456789");
        let interceptor = Interceptor::new_with_named(
            HashMap::new(),
            HashMap::from([("OPENAI_API_KEY".to_string(), fixture)]),
        );
        ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: String::new(),
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap()
    }

    #[test]
    fn path_guard_flags_every_dot_segment_and_encoded_separator_form() {
        for escaping in [
            "/svc/..",
            "/svc/../x",
            "/svc/./x",
            "/svc/%2E%2E/x",
            "/svc/%2e./x",
            "/svc/.%2E/x",
            "/svc/%2e/x",
            "/svc/a%2Fb",
            "/svc/a%5Cb",
            "/svc/a\\b",
            "/svc/.%09./x",
        ] {
            assert!(
                path_has_dot_segment_or_encoded_separator(escaping),
                "not flagged: {escaping}"
            );
        }
        for ordinary in [
            "/svc",
            "/svc/",
            "/svc/v1/chat/completions",
            "/svc/a..b",
            "/svc/...",
            "/svc/.well-known/x",
            "/svc/file.json",
            "/svc/a+b",
            "/svc/%41",
            "/svc//v1/x",
        ] {
            assert!(
                !path_has_dot_segment_or_encoded_separator(ordinary),
                "wrongly flagged: {ordinary}"
            );
        }
    }

    #[tokio::test]
    async fn dot_segment_paths_never_reach_upstream_with_the_route_credential() {
        let mock = crate::test_server::MockServer::start().await;
        let proxy = traversal_probe_proxy(mock.port).await;

        let escapes = [
            "/openai/../admin",
            "/openai/v1/../../admin",
            "/openai/%2e%2e/admin",
            "/openai/%2E%2e/admin",
            "/openai/.%2e/admin",
            "/openai/%2e./admin",
            "/openai/..%2fadmin",
            "/openai/%2e%2e%2fadmin",
            "/openai/v1%2f..%2f..%2fadmin",
            "/openai/..%5cadmin",
            "/openai/./admin",
            "/openai/%2e/admin",
            "/openai/v1/chat/..",
            "/openai/v1/chat/%2e%2e",
            "/openai/v1/chat/%2e%2e?q=1",
        ];
        for target in escapes {
            let status = send_raw_request(proxy.port(), target, &[]).await;
            assert_eq!(status, 400, "dot-segment path was not refused: {target}");
        }
        assert_eq!(
            mock.get_requests().len(),
            0,
            "a dot-segment path reached the upstream"
        );

        // Ordinary paths, including dots inside a segment, still work.
        for target in ["/openai/chat/completions", "/openai/v1/files/a..b.jsonl"] {
            let status = send_raw_request(proxy.port(), target, &[]).await;
            assert_eq!(status, 200, "ordinary path was refused: {target}");
        }
        let paths: Vec<String> = mock.get_requests().into_iter().map(|r| r.path).collect();
        assert_eq!(
            paths,
            vec![
                "/v1/chat/completions".to_string(),
                "/v1/files/a..b.jsonl".to_string()
            ]
        );

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn hop_by_hop_request_headers_are_not_forwarded_upstream() {
        let mock = crate::test_server::MockServer::start().await;
        let proxy = traversal_probe_proxy(mock.port).await;

        let status = send_raw_request(
            proxy.port(),
            "/openai/models",
            &[
                ("Connection", "close, X-Hop-Named"),
                ("X-Hop-Named", "named-by-connection"),
                ("Keep-Alive", "timeout=5"),
                ("Upgrade", "websocket"),
                ("Proxy-Authorization", "Basic cHJveHk6cHJveHk="),
                ("Proxy-Connection", "keep-alive"),
                ("Trailer", "X-Trailer-Field"),
                ("X-End-To-End", "kept"),
            ],
        )
        .await;
        assert_eq!(status, 200);

        let requests = mock.get_requests();
        assert_eq!(requests.len(), 1);
        let forwarded = &requests[0].headers;
        for hop in [
            "x-hop-named",
            "keep-alive",
            "upgrade",
            "proxy-authorization",
            "proxy-connection",
            "trailer",
        ] {
            assert!(
                !forwarded.contains_key(hop),
                "hop-by-hop header forwarded upstream: {hop}"
            );
        }
        assert_eq!(
            forwarded.get("x-end-to-end").map(String::as_str),
            Some("kept")
        );

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    async fn path_auth_probe_proxy(mock_port: u16, session_auth: &str) -> ProxyServer {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "openai".to_string(),
            target_base: format!("http://127.0.0.1:{mock_port}"),
            secret_key: "OPENAI_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            credential_profile: crate::services::CredentialProfile::Standard,
            sdk_base_path: Some("/v1".to_string()),
        });
        let fixture = format!("{}{}", "sk", "-path-auth-fixture-0123456789");
        let interceptor = Interceptor::new_with_named(
            HashMap::new(),
            HashMap::from([("OPENAI_API_KEY".to_string(), fixture)]),
        );
        ProxyServer::start(
            ProxyConfig {
                port: 0,
                proxy_token: session_auth.to_string(),
                allow_query_token_auth: true,
                ..ProxyConfig::default()
            },
            registry,
            interceptor,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn path_auth_segment_is_accepted_only_directly_after_the_route_prefix() {
        let mock = crate::test_server::MockServer::start().await;
        let session_auth = ProxyServer::generate_proxy_token();
        let proxy = path_auth_probe_proxy(mock.port, &session_auth).await;

        // The defined position: `/<route>/_phantom/<session auth>/...`.
        let defined = format!("/openai/_phantom/{session_auth}/models");
        assert_eq!(send_raw_request(proxy.port(), &defined, &[]).await, 200);

        // Anywhere else the pair is never accepted as session auth: with no
        // other auth the request is unauthenticated.
        let misplaced_only = [
            format!("/_phantom/{session_auth}/openai/models"),
            format!("/openai/v1/_phantom/{session_auth}/models"),
            format!("/openai/models/_phantom/{session_auth}"),
        ];
        for (index, target) in misplaced_only.iter().enumerate() {
            let status = send_raw_request(proxy.port(), target, &[]).await;
            assert_eq!(
                status, 401,
                "misplaced path auth segment was accepted: case {index}"
            );
        }

        // An authenticated request with a further `_phantom` segment is
        // refused before routing: the segment is neither silently cut out of
        // the path (which would reach a different upstream endpoint) nor
        // forwarded (where it could carry the session auth upstream).
        let authenticated_with_extra = [
            format!("/openai/_phantom/{session_auth}/_phantom/{session_auth}/models"),
            format!("/openai/_phantom/{session_auth}/v1/%5Fphantom/{session_auth}/models"),
            format!("/openai/_phantom/{session_auth}/v1/_PHANTOM/x/models"),
            format!("/openai/_phantom/{session_auth}/models/_phantom"),
        ];
        for (index, target) in authenticated_with_extra.iter().enumerate() {
            let status = send_raw_request(proxy.port(), target, &[]).await;
            assert_eq!(
                status, 400,
                "extra path auth segment not refused: case {index}"
            );
        }

        let paths: Vec<String> = mock.get_requests().into_iter().map(|r| r.path).collect();
        // Compared without printing: a forwarded path could carry the
        // session auth value.
        assert!(
            paths == vec!["/v1/models".to_string()],
            "unexpected upstream paths"
        );
        assert!(
            !paths
                .iter()
                .any(|path| path.contains(session_auth.as_str())),
            "proxy session auth reached the upstream in a path"
        );

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn header_auth_requests_never_have_a_path_auth_segment_cut_out() {
        // Header-only auth (no URL auth): a `_phantom/<x>` pair deeper in the
        // path used to be removed, so the upstream received `/v1/files` for a
        // request to `/v1/_phantom/<x>/files`. The path is refused instead.
        let mock = crate::test_server::MockServer::start().await;
        let proxy = traversal_probe_proxy(mock.port).await;

        for target in [
            "/openai/v1/_phantom/path_owner/files",
            "/openai/files/_phantom/path_owner",
            "/openai/files/_phantom",
        ] {
            let status = send_raw_request(proxy.port(), target, &[]).await;
            assert_eq!(status, 400, "path auth segment not refused: {target}");
        }
        assert_eq!(
            mock.get_requests().len(),
            0,
            "a rewritten path reached the upstream"
        );

        // Segments that merely contain the marker are ordinary.
        let status = send_raw_request(proxy.port(), "/openai/files/my_phantom_notes", &[]).await;
        assert_eq!(status, 200);
        let paths: Vec<String> = mock.get_requests().into_iter().map(|r| r.path).collect();
        assert_eq!(paths, vec!["/v1/files/my_phantom_notes".to_string()]);

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn multiply_encoded_dot_segments_never_reach_upstream() {
        // An upstream (or an intermediary in front of it) that decodes the
        // path more than once would turn `%252e%252e` into `..`. reqwest
        // forwards it verbatim, so the proxy refuses every decoding layer.
        let mock = crate::test_server::MockServer::start().await;
        let proxy = traversal_probe_proxy(mock.port).await;

        for target in [
            "/openai/%252e%252e/admin",
            "/openai/%252E%252E/admin",
            "/openai/.%252e/admin",
            "/openai/%252e/admin",
            "/openai/%25252e%25252e/admin",
            "/openai/v1%252f..%252fadmin",
            "/openai/a%255cb",
            "/openai/a%25252Fb",
            "/openai/%2525252525252e%2525252525252e/admin",
        ] {
            let status = send_raw_request(proxy.port(), target, &[]).await;
            assert_eq!(status, 400, "multiply encoded path not refused: {target}");
        }
        assert_eq!(
            mock.get_requests().len(),
            0,
            "a multiply encoded dot segment reached the upstream"
        );

        // A single encoded `%` and other double-encoded bytes stay ordinary.
        for target in ["/openai/files/100%25", "/openai/files/%2541"] {
            let status = send_raw_request(proxy.port(), target, &[]).await;
            assert_eq!(status, 200, "ordinary path was refused: {target}");
        }
        let paths: Vec<String> = mock.get_requests().into_iter().map(|r| r.path).collect();
        assert_eq!(
            paths,
            vec![
                "/v1/files/100%25".to_string(),
                "/v1/files/%2541".to_string()
            ]
        );

        proxy.shutdown().await;
        mock.shutdown().await;
    }

    #[tokio::test]
    async fn hop_by_hop_response_headers_are_not_forwarded_to_the_client() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A raw upstream so the response can carry hop-by-hop headers that a
        // hyper server would refuse to send.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
            }
            let body = "{}";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: keep-alive, X-Hop-Named\r\n\
                 X-Hop-Named: named-by-connection\r\n\
                 Keep-Alive: timeout=5\r\n\
                 Proxy-Authenticate: Basic realm=upstream\r\n\
                 Proxy-Connection: keep-alive\r\n\
                 Upgrade: h2c\r\n\
                 Trailer: X-Trailer-Field\r\n\
                 X-End-To-End: kept\r\n\
                 \r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
        });
        let proxy = traversal_probe_proxy(upstream_port).await;

        let resp = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{}/openai/models", proxy.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let headers = resp.headers().clone();
        for hop in [
            "x-hop-named",
            "keep-alive",
            "proxy-authenticate",
            "proxy-connection",
            "upgrade",
            "trailer",
        ] {
            assert!(
                !headers.contains_key(hop),
                "hop-by-hop header forwarded to the client: {hop}"
            );
        }
        assert_eq!(
            headers.get("x-end-to-end").and_then(|v| v.to_str().ok()),
            Some("kept")
        );
        assert_eq!(resp.bytes().await.unwrap().as_ref(), b"{}");

        upstream.await.unwrap();
        proxy.shutdown().await;
    }
}
