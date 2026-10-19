//! LiteLLM proxy as the upstream of a Phantom route (see docs/litellm.md,
//! "LiteLLM as an upstream"). For every header LiteLLM's docs say its proxy
//! reads a virtual key from, a route configured with that header must:
//!
//! - swap the child's `phm_` placeholder for the real key in that header
//!   only, in the documented value format;
//! - never forward the placeholder or the proxy token to LiteLLM;
//! - keep the real key out of the response the child sees when LiteLLM
//!   echoes the header value (whole or partial) in a response header or body.
//!
//! Headers and formats, from LiteLLM's docs (checked 2026-10-19):
//! - https://docs.litellm.ai/docs/auth_overview : `x-litellm-api-key: Bearer
//!   sk-...` (preferred), `Authorization: Bearer sk-...` (standard fallback),
//!   and vendor aliases `API-Key`, `x-api-key`, `x-goog-api-key`,
//!   `Ocp-Apim-Subscription-Key` (no value format shown; tested bare).
//! - https://docs.litellm.ai/docs/proxy/virtual_keys and
//!   https://docs.litellm.ai/docs/proxy/config_settings :
//!   `general_settings.litellm_key_header_name`, example
//!   `X-Litellm-Key: Bearer $LITELLM_API_KEY`.
//!
//! Routes are built by `ServiceRegistry::from_config` from a
//! `.phantom.toml`-style service, as `phantom start` builds them, then pointed
//! at a plain-HTTP mock on 127.0.0.1 (config routes are always `https://`).
//! Hermetic: loopback only, obvious fake keys.
//!
//! Run: cargo test -p phantom-secrets-proxy --test litellm_upstream_headers_test

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use phantom_core::config::ServiceConfig;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const REAL: &str = "sk-FAKElitellmVirtualKey0123456789abcdef";
const PHM: &str = "phm_4444aaaa5555bbbb6666cccc7777dddd8888eeee9999ffff0000aaaa1111bbbb";
const PROXY_TOKEN: &str = "fake-proxy-token-for-litellm-upstream-test-0001";

/// (header, header_format, source URL) for every documented key header.
const DOCUMENTED: [(&str, &str, &str); 7] = [
    (
        "x-litellm-api-key",
        "Bearer {secret}",
        "https://docs.litellm.ai/docs/auth_overview",
    ),
    (
        "Authorization",
        "Bearer {secret}",
        "https://docs.litellm.ai/docs/auth_overview",
    ),
    (
        "X-Litellm-Key",
        "Bearer {secret}",
        "https://docs.litellm.ai/docs/proxy/virtual_keys",
    ),
    (
        "API-Key",
        "{secret}",
        "https://docs.litellm.ai/docs/auth_overview",
    ),
    (
        "x-api-key",
        "{secret}",
        "https://docs.litellm.ai/docs/auth_overview",
    ),
    (
        "x-goog-api-key",
        "{secret}",
        "https://docs.litellm.ai/docs/auth_overview",
    ),
    (
        "Ocp-Apim-Subscription-Key",
        "{secret}",
        "https://docs.litellm.ai/docs/auth_overview",
    ),
];

#[derive(Clone, Debug, Default)]
struct Seen {
    headers: Vec<(String, String)>,
    body: String,
}

/// Mock LiteLLM: records the request and echoes the value of `echo_header`
/// back, whole and as its last half, in a response header and a JSON error.
async fn start_mock(echo_header: String) -> (u16, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = seen_task.clone();
            let echo_header = echo_header.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let seen = seen.clone();
                    let echo_header = echo_header.clone();
                    async move {
                        let headers: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(k, v)| {
                                (
                                    k.to_string(),
                                    String::from_utf8_lossy(v.as_bytes()).to_string(),
                                )
                            })
                            .collect();
                        let echoed = req
                            .headers()
                            .get(echo_header.as_str())
                            .map(|v| String::from_utf8_lossy(v.as_bytes()).to_string())
                            .unwrap_or_default();
                        let body = String::from_utf8_lossy(
                            &req.into_body().collect().await.unwrap().to_bytes(),
                        )
                        .to_string();
                        seen.lock().unwrap().push(Seen { headers, body });
                        let half = &echoed[echoed.len() / 2..];
                        let json = format!(
                            r#"{{"error":{{"message":"Authentication Error, Invalid proxy server token passed. Received API Key = {echoed}, Key Hash (Token) = none","tail":"{half}","type":"auth_error"}}}}"#
                        );
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(401)
                                .header("content-type", "application/json")
                                .header("x-echo-key", echoed.clone())
                                .header("x-echo-tail", half.to_string())
                                .body(Full::new(Bytes::from(json)))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (port, seen)
}

/// A LiteLLM upstream route exactly as `.phantom.toml` would declare it.
fn litellm_service(header: &str, format: &str) -> BTreeMap<String, ServiceConfig> {
    BTreeMap::from([(
        "litellm".to_string(),
        ServiceConfig {
            secret_key: "LITELLM_API_KEY".to_string(),
            pattern: Some("litellm.example.test".to_string()),
            header: Some(header.to_string()),
            header_format: Some(format.to_string()),
            secret_type: "api_key".to_string(),
        },
    )])
}

async fn start_proxy(header: &str, format: &str, mock_port: u16) -> ProxyServer {
    let mut route = ServiceRegistry::from_config(&litellm_service(header, format))
        .match_route("/litellm")
        .expect("config builds a litellm route")
        .0
        .clone();
    assert_eq!(
        route.header, header,
        "config header becomes the route-owned header"
    );
    assert_eq!(route.header_format, format);
    route.target_base = format!("http://127.0.0.1:{mock_port}");
    let mut registry = ServiceRegistry::new();
    registry.add_route(route);

    let token_to_secret = HashMap::from([(
        PHM.to_string(),
        ("LITELLM_API_KEY".to_string(), REAL.to_string()),
    )]);
    let named = HashMap::from([("LITELLM_API_KEY".to_string(), REAL.to_string())]);
    ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: PROXY_TOKEN.to_string(),
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_scoped(token_to_secret, named),
    )
    .await
    .unwrap()
}

fn has_run(text: &str, secret: &str, min: usize) -> bool {
    (0..=secret.len().saturating_sub(min)).any(|i| text.contains(&secret[i..i + min]))
}

#[tokio::test]
async fn every_documented_litellm_key_header_gets_the_real_key_and_never_echoes_it() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let mut failures = Vec::new();

    for (header, format, source) in DOCUMENTED {
        let (mock_port, seen) = start_mock(header.to_ascii_lowercase()).await;
        let proxy = start_proxy(header, format, mock_port).await;
        let child_value = format.replace("{secret}", PHM);

        let resp = client
            .post(format!(
                "http://127.0.0.1:{}/litellm/v1/chat/completions",
                proxy.port()
            ))
            .header("x-phantom-proxy-token", PROXY_TOKEN)
            .header(header, &child_value)
            .header("content-type", "application/json")
            .body(r#"{"model":"gpt-gateway","messages":[{"role":"user","content":"hi"}]}"#)
            .send()
            .await
            .unwrap();
        let mut view = format!("status {}\n", resp.status());
        for (k, v) in resp.headers() {
            view.push_str(&format!("{k}: {}\n", String::from_utf8_lossy(v.as_bytes())));
        }
        view.push_str(&resp.text().await.unwrap());
        proxy.shutdown().await;

        let seen = seen.lock().unwrap().clone();
        let want = format.replace("{secret}", REAL);
        let lname = header.to_ascii_lowercase();
        let values: Vec<&str> = seen
            .first()
            .map(|s| {
                s.headers
                    .iter()
                    .filter(|(k, _)| *k == lname)
                    .map(|(_, v)| v.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let upstream_blob = format!("{seen:?}");

        let mut problems = Vec::new();
        if seen.len() != 1 {
            problems.push(format!("upstream saw {} requests", seen.len()));
        }
        if values != vec![want.as_str()] {
            problems.push(format!(
                "upstream {header} values {values:?}, want exactly one injected value"
            ));
        }
        if !seen.iter().any(|s| s.body.contains("gpt-gateway")) {
            problems.push("request body did not reach LiteLLM".to_string());
        }
        if upstream_blob.contains(PHM) {
            problems.push("phm_ placeholder reached LiteLLM".to_string());
        }
        if upstream_blob.contains(PROXY_TOKEN) {
            problems.push("proxy token reached LiteLLM".to_string());
        }
        if has_run(&view, REAL, 12) {
            problems.push(format!(
                "real key (12+ char run) reached the child:\n{view}"
            ));
        }
        if !view.contains("status 401") {
            problems.push(format!("unexpected child response:\n{view}"));
        }
        if !problems.is_empty() {
            failures.push(format!("{header} ({source}): {}", problems.join("; ")));
        }
    }
    assert!(
        failures.is_empty(),
        "LiteLLM upstream header failures:\n{}",
        failures.join("\n")
    );
}

/// Mock LiteLLM streaming endpoint over raw TCP. It records the value of
/// `echo_header` and answers with a chunked `text/event-stream` that echoes
/// that value split across chunks (first 10 bytes, then the rest), then its
/// last half, then `[DONE]`.
async fn start_sse_mock(echo_header: String) -> (u16, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen = seen_task.clone();
            let echo_header = echo_header.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let head_end = loop {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                let length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while raw.len() < head_end + length {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&raw).to_string());
                let echoed = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.trim()
                            .eq_ignore_ascii_case(&echo_header)
                            .then(|| v.trim().to_string())
                    })
                    .unwrap_or_default();
                let split = echoed.len().min(10);
                let half = &echoed[echoed.len() / 2..];
                let events = [
                    format!(
                        "data: {{\"choices\":[{{\"delta\":{{\"content\":\"key {}",
                        &echoed[..split]
                    ),
                    format!("{}\"}}}}]}}\n\n", &echoed[split..]),
                    format!(
                        "data: {{\"choices\":[{{\"delta\":{{\"content\":\"tail {half}\"}}}}]}}\n\n"
                    ),
                    "data: [DONE]\n\n".to_string(),
                ];
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n")
                    .await;
                for event in events {
                    let _ = stream
                        .write_all(format!("{:x}\r\n{event}\r\n", event.len()).as_bytes())
                        .await;
                    let _ = stream.flush().await;
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, seen)
}

#[tokio::test]
async fn streamed_echoes_of_every_documented_litellm_key_header_are_scrubbed() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let mut failures = Vec::new();

    for (header, format, source) in DOCUMENTED {
        let (mock_port, seen) = start_sse_mock(header.to_string()).await;
        let proxy = start_proxy(header, format, mock_port).await;

        let resp = client
            .post(format!("http://127.0.0.1:{}/litellm/v1/chat/completions", proxy.port()))
            .header("x-phantom-proxy-token", PROXY_TOKEN)
            .header(header, format.replace("{secret}", PHM))
            .header("content-type", "application/json")
            .body(r#"{"model":"gpt-gateway","stream":true,"messages":[{"role":"user","content":"hi"}]}"#)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let view = resp
            .text()
            .await
            .unwrap_or_else(|e| format!("<body error {e}>"));
        proxy.shutdown().await;

        let seen = seen.lock().unwrap().clone();
        let want = format!(
            "{}: {}",
            header.to_ascii_lowercase(),
            format.replace("{secret}", REAL)
        );
        let mut problems = Vec::new();
        if seen.len() != 1
            || !seen[0]
                .to_ascii_lowercase()
                .contains(&want.to_ascii_lowercase())
        {
            problems.push("LiteLLM did not get the real key in the configured header".to_string());
        }
        if seen.iter().any(|s| s.contains(PHM)) {
            problems.push("phm_ placeholder reached LiteLLM".to_string());
        }
        if status != 200 || !view.contains("data: [DONE]") || !view.contains("tail ") {
            problems.push(format!(
                "stream did not complete (status {status}):\n{view}"
            ));
        }
        if has_run(&view, REAL, 12) {
            problems.push(format!(
                "real key (12+ char run) reached the child in the stream:\n{view}"
            ));
        }
        if !problems.is_empty() {
            failures.push(format!("{header} ({source}): {}", problems.join("; ")));
        }
    }
    assert!(
        failures.is_empty(),
        "LiteLLM upstream SSE failures:\n{}",
        failures.join("\n")
    );
}
