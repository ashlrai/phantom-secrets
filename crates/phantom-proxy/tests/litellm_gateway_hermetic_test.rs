//! Hermetic check of the LiteLLM-behind-Phantom flow in `docs/litellm.md`.
//!
//! No LiteLLM install and no network beyond 127.0.0.1. The test plays the
//! LiteLLM client: it holds only a `phm_` session placeholder and the
//! `OPENAI_BASE_URL` shape that `phantom exec` exports
//! (`http://127.0.0.1:<port>/openai/_phantom/<proxy token>/`), and sends the
//! OpenAI-style requests LiteLLM sends. The proxy is built the way
//! `phantom exec` builds it (`Interceptor::new_scoped`, path token auth on),
//! except that the `openai` route targets a plain-HTTP mock on 127.0.0.1.
//!
//! Asserted:
//! - the placeholder is swapped for the real key only at the proxy, only in
//!   the configured header, and only on the way to the configured upstream;
//! - a second mock that no route names never receives a request, whatever the
//!   client or the upstream tries (Host header, absolute-form URI, forwarding
//!   headers, an upstream redirect);
//! - the real key never appears in a response or error body, in any proxy log
//!   line (tracing at TRACE plus stderr), or in the audit ledger.
//!
//! The scenario runs in a child copy of this test binary so the parent can
//! capture all of the child's stdout and stderr and give it its own HOME and
//! `PHANTOM_AUDIT=1` without changing this process's environment.
//!
//! Run: cargo test -p phantom-secrets-proxy --test litellm_gateway_hermetic_test

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use phantom_core::token::PhantomToken;
use phantom_proxy::services::CredentialProfile;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry, ServiceRoute};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CHILD_ENV: &str = "PHANTOM_LITELLM_HERMETIC_CHILD";
const REAL_ENV: &str = "PHANTOM_LITELLM_HERMETIC_REAL";
const CHILD_TEST: &str = "litellm_gateway_scenario_child";
const DONE_MARKER: &str = "LITELLM-HERMETIC-SCENARIO-DONE";

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    /// Everything the upstream observed, as one searchable string.
    fn blob(&self) -> String {
        let mut s = self.path.clone();
        for (k, v) in &self.headers {
            s.push('\n');
            s.push_str(k);
            s.push_str(": ");
            s.push_str(v);
        }
        s.push('\n');
        s.push_str(&String::from_utf8_lossy(&self.body));
        s
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// OpenAI-compatible mock on 127.0.0.1. `/v1/chat/completions` answers like
/// OpenAI; `/v1/echo-error` reflects the received Authorization in a 401
/// body; `/v1/echo-stream` reflects it in an SSE event; `/v1/redirect` sends a
/// 307 to `redirect_to`. Every request is recorded.
async fn start_mock(redirect_to: Option<String>) -> (u16, Log) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let log = log2.clone();
            let redirect_to = redirect_to.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let log = log.clone();
                    let redirect_to = redirect_to.clone();
                    async move { mock_handle(req, log, redirect_to).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (port, log)
}

async fn mock_handle(
    req: Request<Incoming>,
    log: Log,
    redirect_to: Option<String>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_default();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let auth = headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let body = req.into_body().collect().await?.to_bytes().to_vec();
    log.lock().unwrap().push(Seen {
        path: path.clone(),
        headers,
        body,
    });

    let json = |status: u16, body: String| {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    };
    let resp = if path.starts_with("/v1/chat/completions") {
        json(
            200,
            r#"{"id":"chatcmpl-mock","object":"chat.completion","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_string(),
        )
    } else if path.starts_with("/v1/echo-error") {
        // A misbehaving upstream that reflects the credential it received.
        json(
            401,
            format!(
                r#"{{"error":{{"message":"Incorrect API key provided: {auth}","type":"invalid_request_error"}}}}"#
            ),
        )
    } else if path.starts_with("/v1/echo-stream") {
        let token = auth.trim_start_matches("Bearer ");
        let sse = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"key {token}\"}}}}]}}\n\ndata: [DONE]\n\n"
        );
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(Full::new(Bytes::from(sse)))
            .unwrap()
    } else if path.starts_with("/v1/redirect") {
        Response::builder()
            .status(307)
            .header("location", redirect_to.unwrap_or_default())
            .body(Full::new(Bytes::new()))
            .unwrap()
    } else {
        json(404, r#"{"error":{"message":"not found"}}"#.to_string())
    };
    Ok(resp)
}

/// Send one raw HTTP/1.1 request to the proxy and return the full response.
async fn raw(port: u16, request: String) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

fn assert_clean(what: &str, text: &str, real: &str) {
    assert!(!text.contains(real), "{what} contained the real key");
}

/// The scenario. A no-op unless started by the parent test below.
#[tokio::test]
async fn litellm_gateway_scenario_child() {
    if std::env::var(CHILD_ENV).ok().as_deref() != Some("1") {
        return;
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let real = std::env::var(REAL_ENV).expect("real key env");

    // B: a host no route names. It must never be contacted.
    let (b_port, b_log) = start_mock(None).await;
    let b_url = format!("http://127.0.0.1:{b_port}");
    // A: the configured upstream. Its redirect points at B.
    let (a_port, a_log) = start_mock(Some(format!("{b_url}/v1/stolen"))).await;

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "openai".to_string(),
        target_base: format!("http://127.0.0.1:{a_port}"),
        secret_key: "OPENAI_API_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
        credential_profile: CredentialProfile::Standard,
        sdk_base_path: Some("/v1".to_string()),
    });

    // Same construction as `phantom exec`: a fresh session placeholder that
    // maps to (name, real value), plus the name map for header injection.
    let placeholder = PhantomToken::generate().as_str().to_string();
    assert!(placeholder.starts_with("phm_"));
    let mut scoped = HashMap::new();
    scoped.insert(
        placeholder.clone(),
        ("OPENAI_API_KEY".to_string(), real.clone()),
    );
    let mut named = HashMap::new();
    named.insert("OPENAI_API_KEY".to_string(), real.clone());
    let proxy_token = ProxyServer::generate_proxy_token();
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: proxy_token.clone(),
            allow_query_token_auth: true,
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_scoped(scoped, named),
    )
    .await
    .expect("proxy start");
    let port = proxy.port();

    // What LiteLLM gets from `phantom exec`: OPENAI_BASE_URL and OPENAI_API_KEY.
    let api_base = format!("http://127.0.0.1:{port}/openai/_phantom/{proxy_token}/");
    // Never follow redirects in the client either, so anything B receives
    // could only have come from the proxy.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let post = |path: &str, body: String| {
        client
            .post(format!("{api_base}{path}"))
            .header("authorization", format!("Bearer {placeholder}"))
            .header("content-type", "application/json")
            .body(body)
    };
    let chat_body = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;

    // 1. Normal LiteLLM call: real key injected at the proxy, only for A.
    let r = post("chat/completions", chat_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_clean("chat response", &r.text().await.unwrap(), &real);
    {
        let a = a_log.lock().unwrap();
        assert_eq!(a.len(), 1, "A got exactly the one chat call");
        assert_eq!(a[0].path, "/v1/chat/completions");
        assert_eq!(
            a[0].header("authorization"),
            Some(format!("Bearer {real}").as_str())
        );
        let blob = a[0].blob();
        assert!(!blob.contains(&placeholder), "A saw the phm_ placeholder");
        assert!(!blob.contains(&proxy_token), "A saw the proxy token");
        assert_eq!(
            blob.matches(real.as_str()).count(),
            1,
            "real key only in Authorization"
        );
    }

    // 2. The placeholder is only swapped in the configured header: a copy in
    //    the request body (for example a client-side api_key) stays a
    //    placeholder and is never resolved into the real key.
    let body_with_key = format!(
        r#"{{"model":"gpt-4o-mini","api_key":"{placeholder}","messages":[{{"role":"user","content":"{placeholder}"}}]}}"#
    );
    let r = post("chat/completions", body_with_key)
        .send()
        .await
        .unwrap();
    assert_clean(
        "chat response (body placeholder)",
        &r.text().await.unwrap(),
        &real,
    );
    {
        let a = a_log.lock().unwrap();
        let last = a.last().unwrap();
        let body = String::from_utf8_lossy(&last.body);
        assert!(
            !body.contains(&real),
            "body placeholder was resolved to the real key"
        );
        assert_eq!(
            last.header("authorization"),
            Some(format!("Bearer {real}").as_str())
        );
    }

    // 3. Attempts to steer the call to B. None may reach B.
    let a_before = a_log.lock().unwrap().len();
    let host_override = raw(
        port,
        format!(
            "POST /openai/_phantom/{proxy_token}/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{b_port}\r\nAuthorization: Bearer {placeholder}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{chat_body}",
            chat_body.len()
        ),
    )
    .await;
    assert_clean("Host-override response", &host_override, &real);
    let absolute = raw(
        port,
        format!(
            "POST {b_url}/v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{b_port}\r\nAuthorization: Bearer {placeholder}\r\nX-Phantom-Proxy-Token: {proxy_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{chat_body}",
            chat_body.len()
        ),
    )
    .await;
    assert_clean("absolute-form response", &absolute, &real);
    let forwarded = post("chat/completions", chat_body.to_string())
        .header("x-forwarded-host", format!("127.0.0.1:{b_port}"))
        .header("forwarded", format!("host=127.0.0.1:{b_port}"))
        .header("x-original-url", format!("{b_url}/v1/chat/completions"))
        .send()
        .await
        .unwrap();
    assert_clean(
        "forwarding-headers response",
        &forwarded.text().await.unwrap(),
        &real,
    );
    {
        // Any request that did go upstream went to A, never to B.
        let a = a_log.lock().unwrap();
        for seen in &a[a_before..] {
            assert!(
                seen.path.starts_with("/v1/"),
                "unexpected upstream path {}",
                seen.path
            );
        }
    }

    // 4. Upstream redirect to B: the proxy must not follow it.
    let r = post("redirect", chat_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 307, "redirect is returned, not followed");
    assert_clean("redirect response", &format!("{:?}", r.headers()), &real);
    assert_clean("redirect body", &r.text().await.unwrap(), &real);

    // 5. Proxy-made errors: wrong proxy token, unknown route, no route token.
    let bad_token = client
        .post(format!(
            "http://127.0.0.1:{port}/openai/_phantom/{}/chat/completions",
            "0".repeat(proxy_token.len())
        ))
        .header("authorization", format!("Bearer {placeholder}"))
        .body(chat_body)
        .send()
        .await
        .unwrap();
    assert!(
        bad_token.status().is_client_error(),
        "wrong proxy token rejected"
    );
    assert_clean(
        "wrong-token error body",
        &bad_token.text().await.unwrap(),
        &real,
    );
    let unknown = client
        .post(format!(
            "http://127.0.0.1:{port}/not-a-route/_phantom/{proxy_token}/chat/completions"
        ))
        .header("authorization", format!("Bearer {placeholder}"))
        .body(chat_body)
        .send()
        .await
        .unwrap();
    assert!(unknown.status().is_client_error(), "unknown route rejected");
    assert_clean(
        "unknown-route error body",
        &unknown.text().await.unwrap(),
        &real,
    );
    let no_auth = client
        .post(format!("http://127.0.0.1:{port}/openai/chat/completions"))
        .header("authorization", format!("Bearer {placeholder}"))
        .body(chat_body)
        .send()
        .await
        .unwrap();
    assert!(
        no_auth.status().is_client_error(),
        "missing proxy token rejected"
    );
    assert_clean("no-token error body", &no_auth.text().await.unwrap(), &real);

    // 6. Upstream reflects the key in an error body and in an SSE stream:
    //    the proxy must scrub both before LiteLLM sees them.
    let r = post("echo-error", chat_body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let body = r.text().await.unwrap();
    assert_clean("reflected upstream error body", &body, &real);
    assert!(
        body.contains("Incorrect API key provided"),
        "error body otherwise intact: {body}"
    );
    let r = post("echo-stream", r#"{"stream":true}"#.to_string())
        .send()
        .await
        .unwrap();
    let stream = r.text().await.unwrap();
    assert_clean("reflected SSE stream", &stream, &real);
    assert!(
        stream.contains("data: [DONE]"),
        "stream otherwise intact: {stream}"
    );

    // B never saw a single request.
    assert!(
        b_log.lock().unwrap().is_empty(),
        "the non-configured host received {:?}",
        b_log.lock().unwrap()
    );
    // Every key-bearing request A saw carried the real key only in Authorization.
    // The placeholder never reached A in a header (case 2 leaves it in the body on purpose).
    for seen in a_log.lock().unwrap().iter() {
        assert!(
            !seen.headers.iter().any(|(_, v)| v.contains(&placeholder)),
            "placeholder reached A in a header"
        );
        if let Some(auth) = seen.header("authorization") {
            assert_eq!(auth, format!("Bearer {real}"));
        }
    }
    println!("{DONE_MARKER}");
}

#[test]
fn litellm_gateway_real_key_stays_at_proxy() {
    let home = tempfile::tempdir().unwrap();
    // Made-up, key-shaped test value. Not a credential.
    let real = format!("sk-proj-{}", "a1B2c3D4e5F6g7H8i9J0".repeat(3));
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args([CHILD_TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .env(REAL_ENV, &real)
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("PHANTOM_AUDIT", "1")
        .env_remove("PHANTOM_AUDIT_ENCRYPTION")
        .env_remove("RUST_LOG")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .output()
        .expect("run scenario child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The child's own copy of the key comes from its environment; the env is
    // not printed anywhere, so any occurrence below is a leak.
    assert!(
        out.status.success() && stdout.contains(DONE_MARKER),
        "scenario failed.\nstdout:\n{}\nstderr:\n{}",
        stdout.replace(&real, "<REAL>"),
        stderr.replace(&real, "<REAL>")
    );
    // The capture really holds proxy logs (TRACE subscriber on stderr).
    assert!(
        stderr.contains("Phantom proxy listening"),
        "proxy log was not captured"
    );
    assert!(
        stderr.contains("SECURITY WARNING"),
        "leak warning was not captured"
    );
    assert!(
        !stdout.contains(&real),
        "child stdout contained the real key"
    );
    assert!(
        !stderr.contains(&real),
        "proxy log or stderr contained the real key"
    );

    // The audit ledger exists, recorded the intercepted leak, and holds no value.
    let audit = home.path().join(".phantom").join("audit.log");
    let ledger = std::fs::read_to_string(&audit).expect("audit ledger written");
    assert!(
        ledger.contains("proxy.response_leak"),
        "audit ledger missed the leak event"
    );
    assert!(
        !ledger.contains(&real),
        "audit ledger contained the real key"
    );
    // Nothing else written under HOME holds it either.
    let mut stack = vec![home.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(&real),
                    "{} contained the real key",
                    path.display()
                );
            }
        }
    }
}
