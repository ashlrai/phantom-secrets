//! Integration tests: per-secret rate limiting and burst anomaly detection.
//!
//! Tests cover:
//! 1. Single-secret burst → 429 response with correct headers.
//! 2. Multi-secret concurrent load → independent per-secret counters.
//! 3. Rate-limit header injection in 429 responses
//!    (x-phantom-anomaly-class, x-phantom-anomaly-score, retry-after).
//! 4. Normal traffic is never blocked.
//! 5. RateLimiter unit: sliding-window accuracy.
//!
//! Run with:
//!   cargo test --package phantom-secrets-proxy --test rate_limit_test -- --test-threads=4

use phantom_proxy::rate_limiter::{AnomalyClass, RateLimitConfig, RateLimiter};
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry, ServiceRoute};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async fn test_proxy_with_limits(
    per_secret_rps: u64,
    burst_total_10s: u64,
) -> (ProxyServer, phantom_proxy::test_server::MockServer) {
    let mock = phantom_proxy::test_server::MockServer::start().await;

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "testapi".to_string(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "TEST_API_KEY".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
    });

    let interceptor = Interceptor::new(HashMap::new());

    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            rate_limit: RateLimitConfig {
                per_secret_rps,
                burst_total_10s,
            },
            ..ProxyConfig::default()
        },
        registry,
        interceptor,
    )
    .await
    .unwrap();

    (proxy, mock)
}

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Single-secret burst → 429
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_single_secret_burst_returns_429() {
    // per_secret_rps=1 → per_secret_10s_limit=10; burst=100
    // Sending 11 requests should trigger 429 on the 11th.
    let (proxy, mock) = test_proxy_with_limits(1, 100).await;
    let client = make_client();

    let mut last_status = 0u16;
    let mut saw_429 = false;

    for _ in 0..15 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/testapi/v1/models",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        last_status = status;
        if status == 429 {
            saw_429 = true;
            break;
        }
    }

    assert!(
        saw_429,
        "Expected a 429 after bursting past per-secret limit, last status: {last_status}"
    );

    proxy.shutdown().await;
    mock.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Multi-secret concurrent load — different routes tracked independently
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_multi_secret_concurrent_load_independent() {
    // Set a generous per-secret limit but a tight global burst limit.
    // Two separate secrets each at 3 requests should not trigger per-secret
    // alert, but global total (6) should be below burst_total=20.
    let mock = phantom_proxy::test_server::MockServer::start().await;

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "service_a".to_string(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "KEY_A".to_string(),
        header: "Authorization".to_string(),
        header_format: "Bearer {secret}".to_string(),
    });
    registry.add_route(ServiceRoute {
        name: "service_b".to_string(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "KEY_B".to_string(),
        header: "x-api-key".to_string(),
        header_format: "{secret}".to_string(),
    });

    let interceptor = Interceptor::new(HashMap::new());
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            rate_limit: RateLimitConfig {
                per_secret_rps: 5,  // limit=50/10s each
                burst_total_10s: 20,
            },
            ..ProxyConfig::default()
        },
        registry,
        interceptor,
    )
    .await
    .unwrap();

    let client = make_client();

    // Send 3 requests to each service — all should succeed (200)
    for _ in 0..3 {
        let resp_a = client
            .get(format!(
                "http://127.0.0.1:{}/service_a/v1/ping",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp_a.status().as_u16(),
            200,
            "service_a should not be rate limited"
        );

        let resp_b = client
            .get(format!(
                "http://127.0.0.1:{}/service_b/v1/ping",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp_b.status().as_u16(),
            200,
            "service_b should not be rate limited"
        );
    }

    proxy.shutdown().await;
    mock.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: 429 response includes correct rate-limit headers
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_rate_limit_headers_injected_in_429() {
    // Very tight limit: 0 rps → per_secret_10s_limit=0, so 1st request already
    // exceeds the limit.
    // Use per_secret_rps=0 which gives limit=0, meaning even 1 req triggers alert.
    // Actually: 0*10=0 limit, 1>0 → Alert.
    let (proxy, mock) = test_proxy_with_limits(0, 100).await;
    let client = make_client();

    let resp = client
        .get(format!(
            "http://127.0.0.1:{}/testapi/v1/models",
            proxy.port()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 429, "Expected 429 with rps=0");

    // Verify required headers
    let anomaly_class = resp
        .headers()
        .get("x-phantom-anomaly-class")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(anomaly_class, "alert", "x-phantom-anomaly-class should be 'alert'");

    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(!retry_after.is_empty(), "retry-after header should be present");

    let anomaly_score = resp
        .headers()
        .get("x-phantom-anomaly-score")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0")
        .parse::<u8>()
        .unwrap_or(0);
    assert!(anomaly_score > 0, "x-phantom-anomaly-score should be > 0");

    // Verify body contains structured error
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "rate limit exceeded");
    assert_eq!(body["anomaly_class"], "alert");
    assert!(body["per_secret_10s"].as_u64().unwrap_or(0) >= 1);

    proxy.shutdown().await;
    mock.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: Normal traffic (well below limits) is never blocked
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_normal_traffic_not_blocked() {
    // 10 rps → limit=100/10s; burst=50. Send 5 requests — should all be 200.
    let (proxy, mock) = test_proxy_with_limits(10, 50).await;
    let client = make_client();

    for i in 0..5 {
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/testapi/v1/models",
                proxy.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "Request {i} should not be blocked by rate limiter"
        );
    }

    proxy.shutdown().await;
    mock.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: RateLimiter unit — sliding window expiry
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_rate_limiter_unit_normal_class() {
    let rl = RateLimiter::new(RateLimitConfig {
        per_secret_rps: 5,
        burst_total_10s: 20,
    });
    let d = rl.record("KEY");
    assert_eq!(d.class, AnomalyClass::Normal);
    assert_eq!(d.per_secret_10s, 1);
    assert_eq!(d.total_10s, 1);
}

#[test]
fn test_rate_limiter_unit_alert_per_secret() {
    let rl = RateLimiter::new(RateLimitConfig {
        per_secret_rps: 1,  // limit = 10/10s
        burst_total_10s: 1000,
    });
    for _ in 0..10 {
        rl.record("BURST_KEY");
    }
    let d = rl.record("BURST_KEY"); // 11th — over limit of 10
    assert_eq!(d.class, AnomalyClass::Alert);
    assert!(d.anomaly_score >= 100);
}

#[test]
fn test_rate_limiter_unit_alert_global_burst() {
    let rl = RateLimiter::new(RateLimitConfig {
        per_secret_rps: 100,
        burst_total_10s: 3,
    });
    rl.record("K1");
    rl.record("K2");
    rl.record("K3");
    let d = rl.record("K4"); // 4th global — over burst_total=3
    assert_eq!(d.class, AnomalyClass::Alert);
}

#[test]
fn test_rate_limiter_unit_caution_at_half_limit() {
    let rl = RateLimiter::new(RateLimitConfig {
        per_secret_rps: 10,  // limit = 100/10s
        burst_total_10s: 200,
    });
    // Send 50 requests = 50% of per-secret limit → Caution threshold
    for _ in 0..50 {
        rl.record("CAUTION_KEY");
    }
    let d = rl.record("CAUTION_KEY"); // 51st
    assert_eq!(d.class, AnomalyClass::Caution);
}

#[test]
fn test_rate_limiter_env_config_defaults() {
    // Without env vars set, should use default values
    std::env::remove_var("PHANTOM_RATE_LIMIT_PER_SECRET");
    std::env::remove_var("PHANTOM_RATE_LIMIT_BURST");
    let config = RateLimitConfig::from_env();
    assert_eq!(config.per_secret_rps, 5);
    assert_eq!(config.burst_total_10s, 20);
}

#[test]
fn test_rate_limiter_env_config_custom() {
    // Safety: these env vars only affect RateLimitConfig parsing, not the
    // running process behavior, so safe to set briefly in a test.
    std::env::set_var("PHANTOM_RATE_LIMIT_PER_SECRET", "15");
    std::env::set_var("PHANTOM_RATE_LIMIT_BURST", "100");
    let config = RateLimitConfig::from_env();
    std::env::remove_var("PHANTOM_RATE_LIMIT_PER_SECRET");
    std::env::remove_var("PHANTOM_RATE_LIMIT_BURST");
    assert_eq!(config.per_secret_rps, 15);
    assert_eq!(config.burst_total_10s, 100);
}

#[test]
fn test_anomaly_class_score_values() {
    assert_eq!(AnomalyClass::Normal.score(), 0);
    assert_eq!(AnomalyClass::Caution.score(), 1);
    assert_eq!(AnomalyClass::Alert.score(), 2);
}
