//! Process-isolated refusal tests; no upstream request may escape admission.
use phantom_proxy::{
    CredentialProfile, Interceptor, ProxyConfig, ProxyServer, ServiceRegistry, ServiceRoute,
};
use std::collections::HashMap;

#[tokio::test]
async fn unknown_engine_and_unwritable_audit_never_dispatch_credentials() {
    let home = tempfile::tempdir().unwrap();
    // SAFETY: the only test in this integration binary; set before proxy tasks.
    unsafe {
        std::env::set_var("HOME", home.path());
        std::env::set_var("PHANTOM_ENGINE_ID", "synthetic-unknown-engine");
    }
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "audit-test".into(),
        target_base: format!("http://{}", upstream.local_addr().unwrap()),
        secret_key: "AUDIT_TEST_KEY".into(),
        header: "Authorization".into(),
        header_format: "Bearer {secret}".into(),
        credential_profile: CredentialProfile::Standard,
        sdk_base_path: None,
    });
    let interceptor = Interceptor::new_scoped(
        HashMap::new(),
        HashMap::from([("AUDIT_TEST_KEY".into(), "synthetic-proxy-credential".into())]),
    );
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: "synthetic-proxy-bearer".into(),
            ..ProxyConfig::default()
        },
        registry.clone(),
        interceptor.clone(),
    )
    .await
    .unwrap();
    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/audit-test/v1/models?ignored=synthetic-query",
            proxy.port()
        ))
        .header("x-phantom-proxy-token", "synthetic-proxy-bearer")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert!(matches!(upstream.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    proxy.shutdown().await;
    let log = home.path().join(".phantom/audit.log");
    let content = std::fs::read_to_string(&log).unwrap();
    for forbidden in [
        "synthetic-proxy-credential",
        "synthetic-proxy-bearer",
        "synthetic-unknown-engine",
        "synthetic-query",
    ] {
        assert!(!content.contains(forbidden));
    }
    let event = content
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|event| event["op"] == "engine.refused")
        .unwrap();
    assert_eq!(event["outcome"], "refused");
    assert!(phantom_core::audit::verify_log().unwrap().is_clean());
    // With a recognized engine, an unwritable log still blocks the dispatch.
    // The first proxy has shut down, so no spawned task is reading the env.
    unsafe {
        std::env::set_var("PHANTOM_ENGINE_ID", "codex");
    }
    std::fs::rename(&log, log.with_extension("saved")).unwrap();
    std::fs::create_dir(&log).unwrap();
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: "synthetic-proxy-bearer".into(),
            ..ProxyConfig::default()
        },
        registry,
        interceptor,
    )
    .await
    .unwrap();
    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/audit-test/v1/models",
            proxy.port()
        ))
        .header("x-phantom-proxy-token", "synthetic-proxy-bearer")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert!(matches!(upstream.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    proxy.shutdown().await;
}
