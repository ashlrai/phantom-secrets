//! Test-only harness for `examples/litellm/verify.py`. Not part of the shipped
//! CLI and not a supported API.
//!
//! Starts the real Phantom proxy with one `openai` route whose upstream is a
//! plain-HTTP loopback mock (the CLI config path only builds `https://` routes,
//! so this is the only way to test the flow without a real provider). Prints
//! `PORT=<n>` and `TOKEN=<proxy token>` on stdout, then runs until stdin closes.
//!
//! Env: `HARNESS_MOCK_PORT` (mock upstream port), `HARNESS_REAL_VALUE` (the
//! stand-in "real" credential the proxy injects; use a made-up test string).

use phantom_proxy::services::CredentialProfile;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry, ServiceRoute};
use std::collections::HashMap;
use std::io::Read;

#[tokio::main]
async fn main() {
    let mock_port = std::env::var("HARNESS_MOCK_PORT").expect("HARNESS_MOCK_PORT");
    let real = std::env::var("HARNESS_REAL_VALUE").expect("HARNESS_REAL_VALUE");

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "openai".to_string(),
        target_base: format!("http://127.0.0.1:{mock_port}"),
        secret_key: "OPENAI_API_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
        credential_profile: CredentialProfile::Standard,
        // Same as the built-in api.openai.com route: the proxy adds /v1.
        sdk_base_path: Some("/v1".to_string()),
    });
    let mut named = HashMap::new();
    named.insert("OPENAI_API_KEY".to_string(), real);
    let token = ProxyServer::generate_proxy_token();
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: token.clone(),
            // Same as `phantom exec` unless PHANTOM_PROXY_HEADER_AUTH_ONLY is set.
            allow_query_token_auth: true,
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_with_named(HashMap::new(), named),
    )
    .await
    .expect("proxy start");
    println!("PORT={}", proxy.port());
    println!("TOKEN={token}");
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    tokio::task::spawn_blocking(|| {
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
    })
    .await
    .unwrap();
}
