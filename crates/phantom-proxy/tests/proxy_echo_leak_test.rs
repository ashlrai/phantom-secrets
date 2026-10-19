//! The proxy swaps a child's `phm_` placeholder for the real key on the way
//! out. A hostile or careless upstream can echo that real key back. This test
//! runs a fake local upstream that echoes whatever credential it received
//! (Authorization or x-api-key) three ways, and checks that the child sees no
//! part of the real key:
//!
//! 1. inside a JSON error body,
//! 2. inside response headers,
//! 3. inside a streamed (chunked) SSE error event, split across chunks.
//!
//! Hermetic: loopback only, obvious fake keys, no network.
//!
//! Run with:
//!   cargo test -p phantom-secrets-proxy --test proxy_echo_leak_test

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry, ServiceRoute};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const OPENAI_REAL: &str = "fake-openai-key-for-echo-test-0123456789";
const ANTHROPIC_REAL: &str = "fake-anthropic-key-for-echo-test-9876543210";
const OPENAI_PHM: &str = "phm_1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb";
const ANTHROPIC_PHM: &str = "phm_9999cccc8888dddd7777eeee6666ffff5555aaaa4444bbbb3333cccc2222dddd";

type EchoBody = BoxBody<Bytes, Infallible>;

/// The credential the upstream actually received, without any `Bearer ` prefix.
fn received_credential(req: &Request<Incoming>) -> String {
    let raw = req
        .headers()
        .get("authorization")
        .or_else(|| req.headers().get("x-api-key"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    raw.strip_prefix("Bearer ").unwrap_or(&raw).to_string()
}

async fn echo(
    req: Request<Incoming>,
    seen: Arc<Mutex<Vec<String>>>,
) -> Result<Response<EchoBody>, Infallible> {
    let cred = received_credential(&req);
    seen.lock().unwrap().push(cred.clone());
    let path = req.uri().path().to_string();

    let resp = if path.ends_with("/json") {
        let body = format!(
            r#"{{"error":{{"message":"Incorrect API key provided: {cred}","type":"invalid_request_error","echo":"{cred}"}}}}"#
        );
        Response::builder()
            .status(401)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)).boxed())
            .unwrap()
    } else if path.ends_with("/header") {
        Response::builder()
            .status(401)
            .header("content-type", "application/json")
            .header("x-echo-key", cred.clone())
            .header(
                "www-authenticate",
                format!(r#"Bearer realm="api", error="invalid_token", error_description="bad key {cred}""#),
            )
            .body(Full::new(Bytes::from_static(br#"{"error":"unauthorized"}"#)).boxed())
            .unwrap()
    } else {
        // SSE error event, streamed in three chunks with the key split across
        // the chunk boundaries.
        let event =
            format!("event: error\ndata: {{\"error\":{{\"message\":\"invalid key {cred}\"}}}}\n\n");
        let start = event.find(&cred).unwrap_or(0);
        let third = cred.len() / 3;
        let (a, rest) = event.split_at(start + third);
        let (b, c) = rest.split_at(third);
        let chunks: Vec<Result<Frame<Bytes>, Infallible>> = [a, b, c]
            .into_iter()
            .map(|s| Ok(Frame::data(Bytes::from(s.to_string()))))
            .collect();
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(StreamBody::new(tokio_stream::iter(chunks)).boxed())
            .unwrap()
    };
    Ok(resp)
}

async fn start_echo_upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| echo(req, seen.clone())),
                    )
                    .await;
            });
        }
    });
    (port, seen)
}

async fn start_proxy(upstream_port: u16) -> ProxyServer {
    let mut named = HashMap::new();
    named.insert("OPENAI_API_KEY".to_string(), OPENAI_REAL.to_string());
    named.insert("ANTHROPIC_API_KEY".to_string(), ANTHROPIC_REAL.to_string());
    let mut token_map = HashMap::new();
    token_map.insert(OPENAI_PHM.to_string(), OPENAI_REAL.to_string());
    token_map.insert(ANTHROPIC_PHM.to_string(), ANTHROPIC_REAL.to_string());

    let mut registry = ServiceRegistry::new();
    for (name, secret_key, header, format) in [
        (
            "openai",
            "OPENAI_API_KEY",
            "Authorization",
            "Bearer {secret}",
        ),
        ("anthropic", "ANTHROPIC_API_KEY", "x-api-key", "{secret}"),
    ] {
        registry.add_route(ServiceRoute {
            name: name.to_string(),
            target_base: format!("http://127.0.0.1:{upstream_port}"),
            secret_key: secret_key.to_string(),
            header: header.to_string(),
            header_format: format.to_string(),
            credential_profile: phantom_proxy::services::CredentialProfile::Standard,
            sdk_base_path: None,
        });
    }
    ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_with_named(token_map, named),
    )
    .await
    .unwrap()
}

/// Every 8-character run of `secret` that appears in `text`.
fn leaked_fragments(text: &str, secret: &str) -> Vec<String> {
    (0..=secret.len().saturating_sub(8))
        .map(|i| secret[i..i + 8].to_string())
        .filter(|w| text.contains(w.as_str()))
        .collect()
}

/// Everything the child receives: status line, every header, full body.
async fn child_view(resp: reqwest::Response) -> String {
    let mut view = format!("status {}\n", resp.status());
    for (name, value) in resp.headers() {
        view.push_str(&format!(
            "{name}: {}\n",
            String::from_utf8_lossy(value.as_bytes())
        ));
    }
    view.push_str(&resp.text().await.unwrap());
    view
}

async fn run_case(service: &str, header: &str, header_value: &str, mode: &str, real: &str) {
    let (upstream_port, seen) = start_echo_upstream().await;
    let proxy = start_proxy(upstream_port).await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let resp = client
        .post(format!(
            "http://127.0.0.1:{}/{service}/v1/{mode}",
            proxy.port()
        ))
        .header(header, header_value)
        .header("content-type", "application/json")
        .body(r#"{"model":"m","messages":[]}"#)
        .send()
        .await
        .unwrap();
    let view = child_view(resp).await;

    // Precondition: the upstream really received (and so echoed) the real key.
    let creds = seen.lock().unwrap().clone();
    assert_eq!(
        creds,
        vec![real.to_string()],
        "upstream must receive the swapped real key"
    );

    let leaks = leaked_fragments(&view, real);
    assert!(
        leaks.is_empty(),
        "SECURITY: real key reached the child via {service}/{mode}: fragments {leaks:?}\n--- child view ---\n{view}"
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn authorization_echo_in_json_body_does_not_reach_child() {
    run_case(
        "openai",
        "authorization",
        &format!("Bearer {OPENAI_PHM}"),
        "json",
        OPENAI_REAL,
    )
    .await;
}

#[tokio::test]
async fn authorization_echo_in_response_headers_does_not_reach_child() {
    run_case(
        "openai",
        "authorization",
        &format!("Bearer {OPENAI_PHM}"),
        "header",
        OPENAI_REAL,
    )
    .await;
}

#[tokio::test]
async fn authorization_echo_in_streamed_sse_error_does_not_reach_child() {
    run_case(
        "openai",
        "authorization",
        &format!("Bearer {OPENAI_PHM}"),
        "sse",
        OPENAI_REAL,
    )
    .await;
}

#[tokio::test]
async fn x_api_key_echo_in_json_body_does_not_reach_child() {
    run_case(
        "anthropic",
        "x-api-key",
        ANTHROPIC_PHM,
        "json",
        ANTHROPIC_REAL,
    )
    .await;
}

#[tokio::test]
async fn x_api_key_echo_in_response_headers_does_not_reach_child() {
    run_case(
        "anthropic",
        "x-api-key",
        ANTHROPIC_PHM,
        "header",
        ANTHROPIC_REAL,
    )
    .await;
}

#[tokio::test]
async fn x_api_key_echo_in_streamed_sse_error_does_not_reach_child() {
    run_case(
        "anthropic",
        "x-api-key",
        ANTHROPIC_PHM,
        "sse",
        ANTHROPIC_REAL,
    )
    .await;
}
