//! What key-exchange groups does the proxy's upstream TLS client offer?
//!
//! The proxy forwards to upstream APIs over HTTPS with a `reqwest` client built
//! on rustls. Whether that client offers a post-quantum hybrid group
//! (X25519MLKEM768, IANA code point 0x11ec) depends on which rustls crypto
//! provider the build selects, not on Phantom code, so a dependency change can
//! silently flip it. This test makes the outcome visible: it points a route at
//! a raw TCP listener, sends one request through the real proxy, captures the
//! TLS ClientHello the proxy's client sends, and reads the supported_groups
//! extension (RFC 8446 section 4.2.7). It never completes a handshake.
//!
//! The proxy builds its client with the aws-lc-rs provider, which offers
//! X25519MLKEM768 first. This asserts what the client OFFERS. A negotiated group also depends on the
//! upstream server; `tls_pq_negotiation_test.rs` checks negotiation against a
//! local PQ-only server.

use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry, ServiceRoute};
use std::collections::HashMap;
use tokio::io::AsyncReadExt;

const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
/// X25519MLKEM768, draft-ietf-tls-ecdhe-mlkem.
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
/// X-Wing provisional code point requested in draft-connolly-cfrg-xwing-kem.
const GROUP_XWING_REQUESTED: u16 = 0x647a;

fn be16(b: &[u8], at: usize) -> usize {
    ((b[at] as usize) << 8) | b[at + 1] as usize
}

/// Parse the supported_groups list from a TLS ClientHello record.
fn client_hello_groups(rec: &[u8]) -> Vec<u16> {
    assert_eq!(rec[0], 0x16, "not a TLS handshake record");
    assert_eq!(rec[5], 0x01, "not a ClientHello");
    // record header 5, handshake header 4, version 2, random 32
    let mut p = 5 + 4 + 2 + 32;
    p += 1 + rec[p] as usize; // session id
    p += 2 + be16(rec, p); // cipher suites
    p += 1 + rec[p] as usize; // compression methods
    let ext_end = p + 2 + be16(rec, p);
    p += 2;
    while p + 4 <= ext_end {
        let ty = be16(rec, p);
        let len = be16(rec, p + 2);
        if ty == 0x000a {
            let list_len = be16(rec, p + 4);
            return rec[p + 6..p + 6 + list_len]
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
        }
        p += 4 + len;
    }
    panic!("no supported_groups extension in ClientHello");
}

async fn offered_groups() -> Vec<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "probe".to_string(),
        target_base: format!("https://127.0.0.1:{port}"),
        secret_key: "PROBE_API_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
        credential_profile: phantom_proxy::services::CredentialProfile::Standard,
        sdk_base_path: None,
    });
    let mut named = HashMap::new();
    named.insert("PROBE_API_KEY".to_string(), "probe-value".to_string());
    let token = ProxyServer::generate_proxy_token();
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: token.clone(),
            connect_timeout_secs: 5,
            upstream_timeout_secs: 5,
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_with_named(HashMap::new(), named),
    )
    .await
    .unwrap();

    let client_port = proxy.port();
    let sender = tokio::spawn(async move {
        let _ = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{client_port}/probe/v1/models"))
            .header("x-phantom-proxy-token", token)
            .send()
            .await;
    });

    let (mut sock, _) = tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
        .await
        .expect("proxy never connected upstream")
        .unwrap();
    let mut buf = vec![0u8; 16 * 1024];
    let mut got = 0;
    // Read until the whole first TLS record is in.
    loop {
        let n = sock.read(&mut buf[got..]).await.unwrap();
        assert!(n > 0, "upstream connection closed before ClientHello");
        got += n;
        if got >= 5 && got >= 5 + be16(&buf, 3) {
            break;
        }
    }
    drop(sock);
    sender.abort();
    client_hello_groups(&buf[..got])
}

#[tokio::test]
async fn upstream_client_offers_classical_groups() {
    let groups = offered_groups().await;
    eprintln!("offered groups: {groups:04x?}");
    assert!(groups.contains(&GROUP_X25519), "{groups:04x?}");
    assert!(groups.contains(&GROUP_SECP256R1), "{groups:04x?}");
}

/// Records the current post-quantum posture of the upstream TLS client. If a
/// dependency or provider change flips this, the test fails and the change
/// must be reviewed and the docs (`phantom doctor --pq`, README) updated.
#[tokio::test]
async fn upstream_client_pq_group_posture_is_pinned() {
    let groups = offered_groups().await;
    let offers_hybrid = groups.contains(&GROUP_X25519_MLKEM768);
    assert!(!groups.contains(&GROUP_XWING_REQUESTED), "{groups:04x?}");
    // The hybrid group is the client's first preference, classical groups follow.
    assert_eq!(
        groups.first(),
        Some(&GROUP_X25519_MLKEM768),
        "{groups:04x?}"
    );
    assert_eq!(
        offers_hybrid,
        EXPECT_HYBRID_OFFERED,
        "upstream TLS client PQ hybrid offer changed (groups {groups:04x?}); review it and update the docs"
    );
}

const EXPECT_HYBRID_OFFERED: bool = true;

/// `phantom doctor` reports `upstream_offered_key_exchange_groups()`. It must
/// be exactly what goes on the wire, in the same order.
#[tokio::test]
async fn reported_groups_match_the_client_hello() {
    let on_wire = offered_groups().await;
    let reported: Vec<u16> = phantom_proxy::upstream_offered_key_exchange_groups()
        .iter()
        .map(|g| g.code_point)
        .collect();
    assert_eq!(
        reported, on_wire,
        "reported {reported:04x?} vs wire {on_wire:04x?}"
    );
    let names: Vec<String> = phantom_proxy::upstream_offered_key_exchange_groups()
        .into_iter()
        .map(|g| g.name)
        .collect();
    assert_eq!(
        names.first().map(String::as_str),
        Some("X25519MLKEM768"),
        "{names:?}"
    );
}
