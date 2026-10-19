//! Does the proxy's upstream TLS connection actually negotiate X25519MLKEM768?
//!
//! `tls_client_hello_groups_test.rs` shows what the proxy's client OFFERS. This
//! test shows what it NEGOTIATES: a local rustls server on 127.0.0.1 accepts
//! only one key exchange group, the real proxy forwards a request to it, and
//! the server reports the group from its side of the handshake.
//!
//! - Positive: a server that accepts only X25519MLKEM768 completes the
//!   handshake, records X25519MLKEM768, and answers the proxied request.
//! - Negative control: a server that accepts only a group the proxy does not
//!   offer (pure MLKEM768) never completes a handshake, and the proxy answers
//!   502 `tls_handshake_failed`. Without it the positive case could pass for a
//!   reason other than the group.
//!
//! The certificate is self-signed, generated per run (P-256 key from aws-lc-rs,
//! a minimal DER encoder below), and trusted only through the test-only
//! `ProxyServer::start_trusting_test_roots`. Nothing leaves 127.0.0.1. This
//! says nothing about which group a real provider negotiates: that depends on
//! the provider's server.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use phantom_proxy::services::CredentialProfile;
use phantom_proxy::{
    upstream_offered_key_exchange_groups, Interceptor, ProxyConfig, ProxyServer, ServiceRegistry,
    ServiceRoute,
};
use rustls::crypto::{aws_lc_rs as provider, CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// IANA code point of X25519MLKEM768.
const X25519_MLKEM768: u16 = 0x11ec;
/// IANA code point of pure MLKEM768 (not offered by the proxy).
const MLKEM768: u16 = 0x0201;

// ── Minimal DER for one self-signed P-256 certificate ──────────────────────

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend([0x81, len as u8]);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &parts.concat())
}

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0u8];
    content.extend_from_slice(bytes);
    der(0x03, &content)
}

const OID_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];

/// A self-signed certificate for IP 127.0.0.1 and its PKCS#8 key.
fn self_signed_loopback_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();

    let alg = seq(&[OID_ECDSA_SHA256.to_vec()]);
    let name = seq(&[der(
        0x31,
        &seq(&[OID_COMMON_NAME.to_vec(), der(0x0c, b"phantom-pq-test")]),
    )]);
    let validity = seq(&[der(0x17, b"200101000000Z"), der(0x17, b"491231235959Z")]);
    let spki = seq(&[
        seq(&[OID_EC_PUBLIC_KEY.to_vec(), OID_P256.to_vec()]),
        bit_string(key.public_key().as_ref()),
    ]);
    // subjectAltName = iPAddress 127.0.0.1 ([7] IMPLICIT OCTET STRING).
    let san = seq(&[der(0x87, &[127, 0, 0, 1])]);
    let extensions = der(
        0xa3,
        &seq(&[seq(&[OID_SUBJECT_ALT_NAME.to_vec(), der(0x04, &san)])]),
    );
    let tbs = seq(&[
        der(0xa0, &der(0x02, &[2])), // version v3
        der(0x02, &[0x01, 0x23, 0x45, 0x67]),
        alg.clone(),
        name.clone(),
        validity,
        name,
        spki,
        extensions,
    ]);
    let signature = key.sign(&rng, &tbs).unwrap();
    let cert = seq(&[tbs, alg, bit_string(signature.as_ref())]);
    (
        CertificateDer::from(cert),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec())),
    )
}

// ── A TLS upstream that accepts exactly one key exchange group ─────────────

#[derive(Debug, Clone)]
enum Outcome {
    /// Handshake completed; the group the server negotiated.
    Negotiated(u16),
    /// Handshake failed on the server side.
    HandshakeFailed(String),
}

fn start_single_group_upstream(
    group: &'static dyn SupportedKxGroup,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (u16, Arc<Mutex<Vec<Outcome>>>) {
    let provider = CryptoProvider {
        kx_groups: vec![group],
        ..provider::default_provider()
    };
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cfg = Arc::new(cfg);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let recorded = outcomes.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { break };
            let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let mut conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
            let mut handshake_error = None;
            while conn.is_handshaking() {
                if let Err(e) = conn.complete_io(&mut tcp) {
                    handshake_error = Some(e.to_string());
                    break;
                }
            }
            if let Some(e) = handshake_error {
                recorded.lock().unwrap().push(Outcome::HandshakeFailed(e));
                continue;
            }
            let group = conn
                .negotiated_key_exchange_group()
                .map(|g| u16::from(g.name()))
                .unwrap_or(0);
            recorded.lock().unwrap().push(Outcome::Negotiated(group));
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let body = br#"{"ok":true}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = tls.write_all(head.as_bytes());
            let _ = tls.write_all(body);
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.conn.complete_io(tls.sock);
        }
    });
    (port, outcomes)
}

/// Send one request through the real proxy to `https://127.0.0.1:<port>`.
async fn proxy_request(upstream_port: u16, root: CertificateDer<'static>) -> (u16, String) {
    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "pqtest".to_string(),
        target_base: format!("https://127.0.0.1:{upstream_port}"),
        secret_key: "PQ_TEST_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
        credential_profile: CredentialProfile::Standard,
        sdk_base_path: None,
    });
    let mut named = HashMap::new();
    named.insert("PQ_TEST_KEY".to_string(), "test-only-value".to_string());
    let proxy_token = ProxyServer::generate_proxy_token();
    let proxy = ProxyServer::start_trusting_test_roots(
        ProxyConfig {
            port: 0,
            proxy_token: proxy_token.clone(),
            connect_timeout_secs: 5,
            upstream_timeout_secs: 10,
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_with_named(HashMap::new(), named),
        vec![root],
    )
    .await
    .expect("proxy start");
    let resp = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!(
            "http://127.0.0.1:{}/pqtest/v1/models",
            proxy.port()
        ))
        .header("x-phantom-proxy-token", &proxy_token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap())
}

fn wait_for_outcome(outcomes: &Arc<Mutex<Vec<Outcome>>>) -> Vec<Outcome> {
    for _ in 0..100 {
        let got = outcomes.lock().unwrap().clone();
        if !got.is_empty() {
            return got;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Vec::new()
}

#[tokio::test]
async fn proxy_upstream_negotiates_x25519mlkem768_with_a_pq_only_server() {
    let offered: Vec<u16> = upstream_offered_key_exchange_groups()
        .iter()
        .map(|g| g.code_point)
        .collect();
    assert_eq!(
        offered.first(),
        Some(&X25519_MLKEM768),
        "offered {offered:04x?}"
    );

    let (cert, key) = self_signed_loopback_cert();
    let (port, outcomes) =
        start_single_group_upstream(provider::kx_group::X25519MLKEM768, cert.clone(), key);
    let (status, body) = proxy_request(port, cert).await;
    assert_eq!(
        status, 200,
        "proxied request through a PQ-only upstream: {body}"
    );
    assert_eq!(body, r#"{"ok":true}"#);
    let got = wait_for_outcome(&outcomes);
    assert!(
        matches!(got.as_slice(), [Outcome::Negotiated(g)] if *g == X25519_MLKEM768),
        "server side saw {got:?}"
    );
}

#[tokio::test]
async fn negative_control_server_with_a_group_the_proxy_does_not_offer_fails() {
    let offered: Vec<u16> = upstream_offered_key_exchange_groups()
        .iter()
        .map(|g| g.code_point)
        .collect();
    assert!(
        !offered.contains(&MLKEM768),
        "control group must not be offered: {offered:04x?}"
    );
    assert_eq!(u16::from(provider::kx_group::MLKEM768.name()), MLKEM768);

    let (cert, key) = self_signed_loopback_cert();
    let (port, outcomes) =
        start_single_group_upstream(provider::kx_group::MLKEM768, cert.clone(), key);
    let (status, body) = proxy_request(port, cert).await;
    assert_eq!(
        status, 502,
        "no common group must not reach the upstream: {body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["reason"], "tls_handshake_failed", "{body}");
    let got = wait_for_outcome(&outcomes);
    assert!(!got.is_empty(), "the control server never saw a connection");
    for outcome in &got {
        match outcome {
            // The failure must be the missing shared group, not, say, the certificate.
            Outcome::HandshakeFailed(reason) => assert!(
                reason.contains("NoKxGroupsInCommon"),
                "unexpected handshake failure: {reason}"
            ),
            Outcome::Negotiated(g) => {
                panic!("handshake completed with group {g:#06x} without a shared group")
            }
        }
    }
}
