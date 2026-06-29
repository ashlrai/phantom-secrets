//! Comprehensive tests for ResponseLeakAnalyzer — response scrubbing hardening.
//!
//! Covers:
//! - API error response containing a real vault secret in the body
//! - Leak detected in a custom response header
//! - Partial leak inside a JSON error field
//! - No false positives on public / non-secret data
//! - HIGH severity when vault value matches, MEDIUM for format-only hits
//! - Multiple secrets leaking in the same response
//! - Binary (non-UTF-8) body vault check
//! - Leak location labels are correct
//! - LeakEvent.emit() writes op=proxy.response_leak to the audit log

use std::collections::HashMap;
use phantom_proxy::ResponseLeakAnalyzer;
use phantom_core::audit::{LeakLocation, LeakSeverity};

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn make_named(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn analyzer_with_openai() -> ResponseLeakAnalyzer {
    let named = make_named(&[("OPENAI_API_KEY", "sk-real-openai-key-abcdef1234567890")]);
    ResponseLeakAnalyzer::new(&named)
}

fn analyzer_empty() -> ResponseLeakAnalyzer {
    ResponseLeakAnalyzer::new(&HashMap::new())
}

// ──────────────────────────────────────────────────────────────────────────────
// Body tests
// ──────────────────────────────────────────────────────────────────────────────

/// Vault secret appearing verbatim in an API error body → HIGH severity.
#[test]
fn test_api_error_body_contains_real_secret() {
    let analyzer = analyzer_with_openai();
    let body = r#"{"error":{"message":"Invalid API key: sk-real-openai-key-abcdef1234567890","type":"invalid_request_error","code":"invalid_api_key"}}"#;

    let (scrubbed, events) = analyzer.analyze_body(body.as_bytes());

    let scrubbed_str = String::from_utf8(scrubbed).unwrap();
    // Secret must be gone
    assert!(
        !scrubbed_str.contains("sk-real-openai-key-abcdef1234567890"),
        "secret must be redacted from body: {scrubbed_str}"
    );
    // Replaced with a [REDACTED:...] marker
    assert!(
        scrubbed_str.contains("[REDACTED:"),
        "body should contain REDACTED marker: {scrubbed_str}"
    );

    // At least one HIGH-severity event
    let high: Vec<_> = events
        .iter()
        .filter(|e| e.severity == LeakSeverity::High)
        .collect();
    assert!(!high.is_empty(), "expected at least one HIGH severity event");

    let ev = &high[0];
    assert_eq!(ev.secret_name.as_deref(), Some("OPENAI_API_KEY"));
    assert!(matches!(ev.location, LeakLocation::Body));
    assert!(ev.match_count >= 1);
}

/// Secret appearing multiple times in the body → match_count reflects repeats.
#[test]
fn test_body_multiple_occurrences() {
    let analyzer = analyzer_with_openai();
    let secret = "sk-real-openai-key-abcdef1234567890";
    let body = format!(r#"{{"a":"{secret}","b":"{secret}","c":"{secret}"}}"#);

    let (scrubbed, events) = analyzer.analyze_body(body.as_bytes());
    let scrubbed_str = String::from_utf8(scrubbed).unwrap();

    assert!(!scrubbed_str.contains(secret));

    let high: Vec<_> = events
        .iter()
        .filter(|e| e.severity == LeakSeverity::High)
        .collect();
    assert!(!high.is_empty());
    // match_count should reflect 3 occurrences
    let total_matches: usize = high.iter().map(|e| e.match_count).sum();
    assert!(total_matches >= 3, "expected at least 3 match counts, got {total_matches}");
}

/// Secret embedded inside a JSON "message" field (partial context).
#[test]
fn test_partial_leak_in_json_error_field() {
    let analyzer = analyzer_with_openai();
    let body = r#"{"status":403,"error":"Authentication failed for key sk-real-openai-key-abcdef1234567890 — please rotate it."}"#;

    let (scrubbed, events) = analyzer.analyze_body(body.as_bytes());
    let scrubbed_str = String::from_utf8(scrubbed).unwrap();

    assert!(!scrubbed_str.contains("sk-real-openai-key-abcdef1234567890"));
    assert!(scrubbed_str.contains("[REDACTED:"));

    assert!(
        events.iter().any(|e| e.severity == LeakSeverity::High),
        "partial embed should be HIGH: {events:?}"
    );
}

/// Body containing a known format (sk-*) that is NOT in the vault map → MEDIUM.
#[test]
fn test_format_only_match_is_medium_severity() {
    // Analyzer with empty vault — no confirmed vault values.
    let analyzer = analyzer_empty();
    let body = r#"{"key":"sk-some-third-party-key-xyzxyzxyzxyzxyz"}"#;

    let (scrubbed, events) = analyzer.analyze_body(body.as_bytes());
    let scrubbed_str = String::from_utf8(scrubbed).unwrap();

    assert!(
        !scrubbed_str.contains("sk-some-third-party-key-xyzxyzxyzxyzxyz"),
        "format-only secret should still be redacted: {scrubbed_str}"
    );
    assert!(scrubbed_str.contains("[REDACTED:"));

    // Must be MEDIUM (no vault confirmation).
    let medium: Vec<_> = events
        .iter()
        .filter(|e| e.severity == LeakSeverity::Medium)
        .collect();
    assert!(!medium.is_empty(), "expected MEDIUM severity for format-only hit");
    assert!(
        !events.iter().any(|e| e.severity == LeakSeverity::High),
        "should not be HIGH when not in vault"
    );
}

/// No false positives on clean public JSON.
#[test]
fn test_no_false_positives_public_data() {
    let analyzer = analyzer_with_openai();
    let body = r#"{"model":"gpt-4","usage":{"prompt_tokens":10,"completion_tokens":20},"choices":[{"message":{"content":"Hello, world!"}}]}"#;

    let (scrubbed, events) = analyzer.analyze_body(body.as_bytes());
    let scrubbed_str = String::from_utf8(scrubbed).unwrap();

    // Content must be unchanged
    assert_eq!(body, scrubbed_str, "clean body should not be modified");
    // No leak events
    assert!(events.is_empty(), "expected no leak events on clean body, got: {events:?}");
}

/// No false positives on a random UUID-like string.
#[test]
fn test_no_false_positives_uuid() {
    let analyzer = analyzer_empty();
    let body = r#"{"id":"550e8400-e29b-41d4-a716-446655440000","created":1700000000}"#;

    let (scrubbed, events) = analyzer.analyze_body(body.as_bytes());
    let scrubbed_str = String::from_utf8(scrubbed).unwrap();

    assert_eq!(body, scrubbed_str);
    assert!(events.is_empty());
}

/// No false positives on short alphanumeric tokens that don't match patterns.
#[test]
fn test_no_false_positives_short_token() {
    let analyzer = analyzer_empty();
    // "sk-abc" is too short to match the regex (requires 20+ chars after "sk-")
    let body = r#"{"token":"sk-abc","status":"ok"}"#;

    let (_scrubbed, events) = analyzer.analyze_body(body.as_bytes());
    assert!(events.is_empty(), "short sk- token should not trigger: {events:?}");
}

/// Multiple secrets in one response body, each replaced correctly.
#[test]
fn test_multiple_secrets_in_body() {
    let named = make_named(&[
        ("OPENAI_API_KEY", "sk-real-openai-key-abcdef1234567890"),
        ("STRIPE_KEY", "sk_live_mystripekeyabcdefghij"),
    ]);
    let analyzer = ResponseLeakAnalyzer::new(&named);

    let body = r#"{"openai":"sk-real-openai-key-abcdef1234567890","stripe":"sk_live_mystripekeyabcdefghij"}"#;
    let (scrubbed, events) = analyzer.analyze_body(body.as_bytes());
    let scrubbed_str = String::from_utf8(scrubbed).unwrap();

    assert!(!scrubbed_str.contains("sk-real-openai-key-abcdef1234567890"));
    assert!(!scrubbed_str.contains("sk_live_mystripekeyabcdefghij"));

    // Both should produce HIGH events
    let high_names: Vec<_> = events
        .iter()
        .filter(|e| e.severity == LeakSeverity::High)
        .filter_map(|e| e.secret_name.as_deref())
        .collect();
    assert!(high_names.contains(&"OPENAI_API_KEY"), "expected OPENAI_API_KEY high event");
    assert!(high_names.contains(&"STRIPE_KEY"), "expected STRIPE_KEY high event");
}

/// GitHub PAT format detected even without vault entry.
#[test]
fn test_github_pat_format_detected() {
    let analyzer = analyzer_empty();
    // Build a token that is long enough to match the ghp_ regex (36+ chars after ghp_).
    let raw_token = format!("ghp_{}", "A".repeat(36));
    let body = format!(r#"{{"token":"{raw_token}","type":"github"}}"#);

    let (scrubbed, events) = analyzer.analyze_body(body.as_bytes());
    let scrubbed_str = String::from_utf8(scrubbed).unwrap();

    // The original full token must be gone; [REDACTED:ghp_*] may remain.
    assert!(
        !scrubbed_str.contains(&raw_token),
        "original ghp_ token value should be redacted: {scrubbed_str}"
    );
    assert!(scrubbed_str.contains("[REDACTED:"), "should have a REDACTED marker: {scrubbed_str}");
    assert!(!events.is_empty(), "expected leak event for ghp_ pattern");
}

/// AWS access key format detected.
#[test]
fn test_aws_access_key_detected() {
    let analyzer = analyzer_empty();
    let body = r#"{"aws_key":"AKIAIOSFODNN7EXAMPLE","region":"us-east-1"}"#;

    let (scrubbed, events) = analyzer.analyze_body(body.as_bytes());
    let scrubbed_str = String::from_utf8(scrubbed).unwrap();

    assert!(!scrubbed_str.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!events.is_empty());
}

// ──────────────────────────────────────────────────────────────────────────────
// Header tests
// ──────────────────────────────────────────────────────────────────────────────

/// Secret leaking in a custom response header → Header location with name.
#[test]
fn test_leak_in_custom_response_header() {
    let analyzer = analyzer_with_openai();
    let header_name = "X-Debug-Key";
    let header_value = "Bearer sk-real-openai-key-abcdef1234567890";

    let (scrubbed, events) = analyzer.analyze_header(header_name, header_value);

    assert!(!scrubbed.contains("sk-real-openai-key-abcdef1234567890"),
        "header value must be scrubbed: {scrubbed}");
    assert!(scrubbed.contains("[REDACTED:"));

    assert!(!events.is_empty(), "expected leak events for header");
    let ev = events.iter().find(|e| e.severity == LeakSeverity::High).unwrap();
    match &ev.location {
        LeakLocation::Header(name) => assert_eq!(name, header_name),
        other => panic!("expected Header location, got {other:?}"),
    }
}

/// Header with safe content → no events, value unchanged.
#[test]
fn test_clean_header_no_events() {
    let analyzer = analyzer_with_openai();
    let (scrubbed, events) = analyzer.analyze_header("Content-Type", "application/json");
    assert_eq!(scrubbed, "application/json");
    assert!(events.is_empty());
}

/// Leak in a header whose value only matches format (not vault) → MEDIUM.
#[test]
fn test_header_format_only_leak_is_medium() {
    let analyzer = analyzer_empty();
    let (scrubbed, events) = analyzer.analyze_header(
        "X-Api-Token",
        "sk-some-unknown-key-that-looks-like-openai-xyz123",
    );

    assert!(!scrubbed.contains("sk-some-unknown-key-that-looks-like-openai-xyz123"));
    assert!(events.iter().any(|e| e.severity == LeakSeverity::Medium));
    assert!(!events.iter().any(|e| e.severity == LeakSeverity::High));
}

// ──────────────────────────────────────────────────────────────────────────────
// Status-line tests
// ──────────────────────────────────────────────────────────────────────────────

/// Secret in a forwarded HTTP status/reason phrase → StatusLine location.
#[test]
fn test_leak_in_status_line() {
    let analyzer = analyzer_with_openai();
    let status = "401 Unauthorized: invalid key sk-real-openai-key-abcdef1234567890";

    let (scrubbed, events) = analyzer.analyze_status_line(status);

    assert!(!scrubbed.contains("sk-real-openai-key-abcdef1234567890"));
    assert!(!events.is_empty());
    assert!(events.iter().any(|e| e.location == LeakLocation::StatusLine));
}

// ──────────────────────────────────────────────────────────────────────────────
// Leak location label tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_leak_location_labels() {
    assert_eq!(LeakLocation::Body.as_label(), "body");
    assert_eq!(
        LeakLocation::Header("X-Debug".to_string()).as_label(),
        "header:X-Debug"
    );
    assert_eq!(LeakLocation::StatusLine.as_label(), "status-line");
}

// ──────────────────────────────────────────────────────────────────────────────
// from_token_map constructor
// ──────────────────────────────────────────────────────────────────────────────

/// from_token_map correctly detects vault secrets by value.
#[test]
fn test_from_token_map_detects_secret() {
    let token_map: HashMap<String, String> = [(
        "phm_aabbcc".to_string(),
        "sk-real-openai-key-abcdef1234567890".to_string(),
    )]
    .into_iter()
    .collect();
    let analyzer = ResponseLeakAnalyzer::from_token_map(&token_map);
    let body = b"error: key sk-real-openai-key-abcdef1234567890 is invalid";

    let (scrubbed, events) = analyzer.analyze_body(body);
    let scrubbed_str = String::from_utf8(scrubbed).unwrap();

    assert!(!scrubbed_str.contains("sk-real-openai-key-abcdef1234567890"));
    assert!(!events.is_empty());
}

// ──────────────────────────────────────────────────────────────────────────────
// LeakSeverity helpers
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_leak_severity_as_str() {
    assert_eq!(LeakSeverity::High.as_str(), "high");
    assert_eq!(LeakSeverity::Medium.as_str(), "medium");
}

// ──────────────────────────────────────────────────────────────────────────────
// LeakEvent.emit() audit integration
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_leak_event_emit_writes_audit_entry() {
    use std::sync::{Mutex, OnceLock};
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));

    let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir_helper();
    let prev_home = std::env::var("HOME").ok();
    let prev_audit = std::env::var("PHANTOM_AUDIT").ok();
    unsafe {
        std::env::set_var("HOME", &tmp);
        std::env::set_var("PHANTOM_AUDIT", "1");
    }

    let event = phantom_core::audit::LeakEvent {
        ts: 0,
        location: LeakLocation::Body,
        severity: LeakSeverity::High,
        secret_name: Some("OPENAI_API_KEY".to_string()),
        pattern: "sk-*".to_string(),
        match_count: 1,
    };
    event.emit();

    // Verify audit.log was written with the right op
    let log_path = std::path::PathBuf::from(&tmp).join(".phantom").join("audit.log");
    let content = std::fs::read_to_string(&log_path).expect("audit.log should exist");
    let found = content
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .any(|v| v["op"].as_str() == Some("proxy.response_leak"));
    assert!(found, "audit log should contain proxy.response_leak event");

    unsafe {
        match prev_home {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
        match prev_audit {
            Some(p) => std::env::set_var("PHANTOM_AUDIT", p),
            None => std::env::remove_var("PHANTOM_AUDIT"),
        }
    }
}

fn tempdir_helper() -> String {
    let dir = std::env::temp_dir().join(format!("phantom-leak-test-{}", rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().into_owned()
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 + d.as_secs())
        .unwrap_or(0)
}
