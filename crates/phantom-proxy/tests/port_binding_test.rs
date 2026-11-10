//! Port binding behavior: port 0 picks a free ephemeral port, and an explicit
//! port that is already taken fails with an error instead of silently moving.

use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::HashMap;

async fn start(port: u16) -> Result<ProxyServer, Box<dyn std::error::Error + Send + Sync>> {
    ProxyServer::start(
        ProxyConfig {
            port,
            proxy_token: String::new(),
            ..ProxyConfig::default()
        },
        ServiceRegistry::new(),
        Interceptor::new_with_named(HashMap::new(), HashMap::new()),
    )
    .await
}

#[tokio::test]
async fn port_zero_gives_distinct_free_ports() {
    let a = start(0).await.unwrap();
    let b = start(0).await.unwrap();
    assert_ne!(a.port(), 0);
    assert_ne!(a.port(), b.port());
}

#[tokio::test]
async fn explicit_taken_port_returns_error() {
    let a = start(0).await.unwrap();
    let err = start(a.port()).await.err().expect("second bind must fail");
    let io = err.downcast_ref::<std::io::Error>().expect("io error");
    assert_eq!(io.kind(), std::io::ErrorKind::AddrInUse);
}

#[tokio::test]
async fn released_listener_address_can_be_rebound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let proxy = start(addr.port())
        .await
        .expect("released port must be reusable");
    assert_eq!(proxy.port(), addr.port());
    proxy.shutdown().await;
}
