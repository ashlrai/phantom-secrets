//! A proxy must not detach when its owner exits through an error path.

use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start() -> ProxyServer {
    ProxyServer::start(
        ProxyConfig::default(),
        ServiceRegistry::new(),
        Interceptor::new_with_named(HashMap::new(), HashMap::new()),
    )
    .await
    .unwrap()
}

async fn assert_listener_closed(port: u16) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match TcpStream::connect(("127.0.0.1", port)).await {
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => break,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    // A probe can race listener teardown after its handshake.
                    // Retry until refusal proves no listener accepts connections.
                }
                Err(error) => panic!("failed to probe proxy listener: {error}"),
                Ok(connection) => drop(connection),
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropped proxy retained its listener");
}

#[tokio::test]
async fn dropping_owner_before_server_is_polled_releases_listener() {
    let proxy = start().await;
    let port = proxy.port();
    drop(proxy);
    assert_listener_closed(port).await;
}

#[tokio::test]
async fn dropping_owner_closes_an_accepted_connection() {
    let proxy = start().await;
    let port = proxy.port();
    let mut connection = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    connection
        .write_all(b"GET /phantom/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    // A response proves this socket was accepted and has its own connection
    // task. Leave keep-alive open so dropping the owner must close that task.
    let mut response = [0; 1024];
    let received = tokio::time::timeout(Duration::from_secs(2), connection.read(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(received > 0);

    drop(proxy);
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut remaining = Vec::new();
        match connection.read_to_end(&mut remaining).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("failed to observe connection close: {error}"),
        }
    })
    .await
    .expect("dropped proxy retained an accepted connection");
    assert_listener_closed(port).await;
}
