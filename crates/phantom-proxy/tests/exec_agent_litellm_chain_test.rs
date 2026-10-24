//! Hermetic end-to-end chain: agent -> LiteLLM -> Phantom proxy -> provider.
//!
//! Everything runs on 127.0.0.1 with mocks; nothing is installed and no
//! external network is used.
//!
//! - The proxy is built the way `phantom exec` builds it
//!   (`Interceptor::new_scoped` with a fresh `phm_` session placeholder and
//!   path-token auth). Its `openai` route targets a plain-HTTP mock provider.
//!   (The `phantom` binary cannot target a plain-HTTP upstream, so this test
//!   drives the proxy library directly instead of the binary.)
//! - The mock LiteLLM is configured like `docs/litellm.md`: its upstream is
//!   the `OPENAI_BASE_URL` exec exports and its key is the placeholder.
//! - The mock agent is a separate OS process (a child copy of this test
//!   binary) launched with a cleared environment holding only the LiteLLM URL
//!   and a LiteLLM virtual key, the way an agent would be launched next to
//!   LiteLLM.
//!
//! Asserted: the real key exists only on the proxy-to-provider hop. It never
//! appears in the agent's environment or output, in anything LiteLLM
//! receives or sends, or in a response, including when the provider echoes
//! the key back.
//!
//! Run: cargo test -p phantom-secrets-proxy --test exec_agent_litellm_chain_test

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
use tokio::net::TcpListener;

const AGENT_ENV: &str = "PHANTOM_CHAIN_AGENT";
const AGENT_TEST: &str = "chain_mock_agent_child";
const LITELLM_URL_ENV: &str = "LITELLM_BASE_URL";
const LITELLM_KEY_ENV: &str = "LITELLM_API_KEY";
/// A LiteLLM virtual key the agent holds. Obviously fake.
const LITELLM_VIRTUAL_KEY: &str = "sk-litellm-virtual-FAKE-for-tests";

/// One recorded HTTP exchange: what came in and what went back out.
#[derive(Clone, Debug, Default)]
struct Hop {
    request: String,
    response: String,
}

type Log = Arc<Mutex<Vec<Hop>>>;

fn render(req_line: &str, headers: &hyper::HeaderMap, body: &[u8]) -> String {
    let mut s = req_line.to_string();
    for (k, v) in headers {
        s.push_str(&format!("\n{k}: {}", String::from_utf8_lossy(v.as_bytes())));
    }
    s.push('\n');
    s.push_str(&String::from_utf8_lossy(body));
    s
}

async fn serve<F, Fut>(handler: F) -> u16
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let handler = handler.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let handler = handler.clone();
                    async move { Ok::<_, hyper::Error>(handler(req).await) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    port
}

fn json(status: u16, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Mock provider. `/v1/chat/completions` answers OpenAI-style; with
/// `"echo"` in the body it reflects the Authorization it got, like a
/// misbehaving upstream.
async fn start_provider(log: Log) -> u16 {
    serve(move |req: Request<Incoming>| {
        let log = log.clone();
        async move {
            let line = format!("{} {}", req.method(), req.uri());
            let headers = req.headers().clone();
            let auth = headers
                .get("authorization")
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .unwrap_or_default();
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let text = if String::from_utf8_lossy(&body).contains("echo") {
                format!(r#"{{"error":{{"message":"Incorrect API key provided: {auth}"}}}}"#)
            } else {
                r#"{"id":"chatcmpl-mock","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}"#.to_string()
            };
            let status = if text.contains("Incorrect") { 401 } else { 200 };
            log.lock().unwrap().push(Hop {
                request: render(&line, &headers, &body),
                response: text.clone(),
            });
            json(status, text)
        }
    })
    .await
}

/// Mock LiteLLM proxy. Accepts the agent's call with its virtual key and
/// forwards it to `upstream` (the exec-exported OpenAI base URL) with
/// `upstream_key` (the `phm_` placeholder), the way LiteLLM uses
/// `api_base` and `api_key` from its config.
async fn start_litellm(log: Log, upstream: String, upstream_key: String) -> u16 {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    serve(move |req: Request<Incoming>| {
        let log = log.clone();
        let client = client.clone();
        let upstream = upstream.clone();
        let upstream_key = upstream_key.clone();
        async move {
            let line = format!("{} {}", req.method(), req.uri());
            let headers = req.headers().clone();
            let ok = headers.get("authorization").and_then(|v| v.to_str().ok())
                == Some(&format!("Bearer {LITELLM_VIRTUAL_KEY}"));
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let (status, text) = if ok {
                let r = client
                    .post(format!("{upstream}chat/completions"))
                    .header("authorization", format!("Bearer {upstream_key}"))
                    .header("content-type", "application/json")
                    .body(body.clone())
                    .send()
                    .await
                    .unwrap();
                (r.status().as_u16(), r.text().await.unwrap())
            } else {
                (401, r#"{"error":"bad litellm key"}"#.to_string())
            };
            log.lock().unwrap().push(Hop {
                request: render(&line, &headers, &body),
                response: text.clone(),
            });
            json(status, text)
        }
    })
    .await
}

/// The mock agent. A no-op unless launched by the parent test below.
#[tokio::test]
async fn chain_mock_agent_child() {
    if std::env::var(AGENT_ENV).ok().as_deref() != Some("1") {
        return;
    }
    let base = std::env::var(LITELLM_URL_ENV).unwrap();
    let key = std::env::var(LITELLM_KEY_ENV).unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for body in [
        r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#,
        r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"echo"}]}"#,
    ] {
        let r = client
            .post(format!("{base}/v1/chat/completions"))
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        println!("AGENT-STATUS {}", r.status().as_u16());
        println!("AGENT-BODY {}", r.text().await.unwrap());
    }
    // The agent's whole environment, so the parent can check it.
    for (k, v) in std::env::vars() {
        println!("AGENT-ENV {k}={v}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_key_exists_only_on_the_proxy_to_provider_hop() {
    if std::env::var(AGENT_ENV).is_ok() {
        return;
    }
    // Obviously fake "real" key, generated per run.
    let real = format!("sk-proj-FAKE-chain-{}", PhantomToken::generate().as_str());

    let provider_log: Log = Arc::default();
    let provider_port = start_provider(provider_log.clone()).await;

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "openai".to_string(),
        target_base: format!("http://127.0.0.1:{provider_port}"),
        secret_key: "OPENAI_API_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
        credential_profile: CredentialProfile::Standard,
        sdk_base_path: Some("/v1".to_string()),
    });
    let placeholder = PhantomToken::generate().as_str().to_string();
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
    let openai_base = format!(
        "http://127.0.0.1:{}/openai/_phantom/{proxy_token}/",
        proxy.port()
    );

    let litellm_log: Log = Arc::default();
    let litellm_port = start_litellm(litellm_log.clone(), openai_base, placeholder.clone()).await;

    // Launch the agent as its own process with only the LiteLLM settings.
    let exe = std::env::current_exe().unwrap();
    let out = tokio::process::Command::new(exe)
        .args([AGENT_TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env_clear()
        // Windows sockets need SystemRoot; it holds no secret.
        .envs(std::env::var_os("SYSTEMROOT").map(|v| ("SYSTEMROOT", v)))
        .env(AGENT_ENV, "1")
        .env(LITELLM_URL_ENV, format!("http://127.0.0.1:{litellm_port}"))
        .env(LITELLM_KEY_ENV, LITELLM_VIRTUAL_KEY)
        .output()
        .await
        .unwrap();
    let agent_out = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "agent failed: {agent_out}");
    assert!(agent_out.contains("AGENT-STATUS 200"), "{agent_out}");
    assert!(agent_out.contains("AGENT-STATUS 401"), "{agent_out}");
    assert!(
        agent_out.contains("AGENT-ENV PHANTOM_CHAIN_AGENT=1"),
        "{agent_out}"
    );

    // Agent hop: no real key, and the agent never even sees the placeholder.
    assert!(!agent_out.contains(&real), "agent saw the real key");
    assert!(
        !agent_out.contains(&placeholder),
        "agent saw the placeholder"
    );

    // Agent-to-LiteLLM and LiteLLM-to-proxy hops: placeholder only.
    let litellm = litellm_log.lock().unwrap().clone();
    assert_eq!(litellm.len(), 2, "{litellm:?}");
    for hop in &litellm {
        assert!(hop.request.contains(LITELLM_VIRTUAL_KEY));
        assert!(
            !hop.request.contains(&real),
            "LiteLLM received the real key"
        );
        assert!(
            !hop.response.contains(&real),
            "the proxy answered LiteLLM with the real key"
        );
    }

    // Proxy-to-provider hop: the only place the real key exists.
    let provider = provider_log.lock().unwrap().clone();
    assert_eq!(provider.len(), 2, "{provider:?}");
    for hop in &provider {
        assert!(
            hop.request
                .contains(&format!("authorization: Bearer {real}")),
            "{}",
            hop.request
        );
        assert_eq!(hop.request.matches(real.as_str()).count(), 1);
        assert!(
            !hop.request.contains(&placeholder),
            "provider saw the placeholder"
        );
        assert!(
            !hop.request.contains(&proxy_token),
            "provider saw the proxy token"
        );
        assert!(
            !hop.request.contains(LITELLM_VIRTUAL_KEY),
            "provider saw the LiteLLM key"
        );
    }
    // The provider did echo the real key; the proxy must have scrubbed it.
    assert!(provider[1].response.contains(&real));
}
