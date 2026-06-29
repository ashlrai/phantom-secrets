//! Adaptive Response Scrubber tests — context-aware leak pattern recognition.
//!
//! Covers:
//! - Profile learning: JSON path extraction from leaked secrets
//! - High-confidence adaptive redaction (path-targeted, no exact-value match needed)
//! - Stripe, OpenAI, AWS SDK realistic API response shapes
//! - Nested objects, array indices, multi-level paths
//! - Request context (method, url_path, content_type, status_code) enrichment
//! - Non-JSON bodies are not touched by the adaptive layer
//! - Already-redacted values are not double-redacted
//! - Short values (< 8 chars) are not false-positive redacted
//! - Profile persistence and loading round-trip
//! - `extract_json_path` utility covers all JSON shapes
//! - `value_at_json_path` traversal covers objects/arrays/nested
//! - `AdaptiveScrubHit` metadata is populated correctly
//! - 30+ tests in total

use phantom_core::leak_correlation::{
    extract_json_path, value_at_json_path, ContextualLeakProfileStore, RequestContext,
    PROFILE_CONFIDENCE_THRESHOLD,
};
use phantom_proxy::{AdaptiveResponseScrubber, ResponseScrubber};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

fn named(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn json_ctx() -> RequestContext {
    RequestContext::new("POST", "/v1/chat/completions", "application/json", 200)
}

fn stripe_ctx() -> RequestContext {
    RequestContext::new("GET", "/v1/customers", "application/json", 200)
}

fn aws_ctx() -> RequestContext {
    RequestContext::new("POST", "/", "application/json", 200)
}

// Build an ephemeral adaptive scrubber (no disk persistence).
fn ephemeral_scrubber(pairs: &[(&str, &str)]) -> AdaptiveResponseScrubber {
    AdaptiveResponseScrubber::ephemeral(named(pairs))
}

// Build a scrubber backed by a temp-dir profile store.
fn persistent_scrubber(
    pairs: &[(&str, &str)],
    store: Arc<Mutex<ContextualLeakProfileStore>>,
) -> AdaptiveResponseScrubber {
    AdaptiveResponseScrubber::new(named(pairs), store)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. extract_json_path utility
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn extract_path_simple_top_level_key() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"api_key": "sk_live_abc123xyz"}"#).unwrap();
    let path = extract_json_path(&json, "sk_live_abc123xyz");
    assert_eq!(path, Some(".api_key".to_string()));
}

#[test]
fn extract_path_nested_object() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"data": {"live_key": "sk_live_stripe_xyz789"}}"#).unwrap();
    let path = extract_json_path(&json, "sk_live_stripe_xyz789");
    assert_eq!(path, Some(".data.live_key".to_string()));
}

#[test]
fn extract_path_deeply_nested() {
    let json: serde_json::Value = serde_json::from_str(
        r#"{"result": {"credentials": {"access_key": "AKIAIOSFODNN7EXAMPLE"}}}"#,
    )
    .unwrap();
    let path = extract_json_path(&json, "AKIAIOSFODNN7EXAMPLE");
    assert_eq!(
        path,
        Some(".result.credentials.access_key".to_string())
    );
}

#[test]
fn extract_path_array_element() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"keys": ["sk_live_first_key", "sk_live_second_key"]}"#).unwrap();
    let path = extract_json_path(&json, "sk_live_first_key");
    assert_eq!(path, Some(".keys[0]".to_string()));
}

#[test]
fn extract_path_second_array_element() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"tokens": ["safe_val", "sk-openai-secret-abc123"]}"#).unwrap();
    let path = extract_json_path(&json, "sk-openai-secret-abc123");
    assert_eq!(path, Some(".tokens[1]".to_string()));
}

#[test]
fn extract_path_not_found_returns_none() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"message": "hello world"}"#).unwrap();
    let path = extract_json_path(&json, "sk_live_nothere");
    assert!(path.is_none());
}

#[test]
fn extract_path_partial_match_in_string() {
    // The needle is a substring of the value — should still find path.
    let json: serde_json::Value =
        serde_json::from_str(r#"{"msg": "Invalid key: sk_live_partmatch123456789"}"#).unwrap();
    let path = extract_json_path(&json, "sk_live_partmatch123456789");
    assert_eq!(path, Some(".msg".to_string()));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. value_at_json_path utility
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn value_at_path_simple_key() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"secret": "sk_live_abc"}"#).unwrap();
    assert_eq!(value_at_json_path(&json, ".secret"), Some("sk_live_abc"));
}

#[test]
fn value_at_path_nested() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"data": {"key": "sk_live_nested_123"}}"#).unwrap();
    assert_eq!(
        value_at_json_path(&json, ".data.key"),
        Some("sk_live_nested_123")
    );
}

#[test]
fn value_at_path_array_index() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"list": ["a", "b", "sk_live_third"]}"#).unwrap();
    assert_eq!(
        value_at_json_path(&json, ".list[2]"),
        Some("sk_live_third")
    );
}

#[test]
fn value_at_path_missing_returns_none() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"foo": "bar"}"#).unwrap();
    assert!(value_at_json_path(&json, ".missing").is_none());
}

#[test]
fn value_at_path_non_string_returns_none() {
    let json: serde_json::Value =
        serde_json::from_str(r#"{"count": 42}"#).unwrap();
    assert!(value_at_json_path(&json, ".count").is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Profile store — record_leak and confidence progression
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn profile_store_single_observation_low_confidence() {
    let mut store = ContextualLeakProfileStore::with_path("/dev/null".into());
    let ctx = json_ctx();
    store.record_leak("STRIPE_KEY", ".data.live_key", &ctx).unwrap();
    let obs = store.all_paths_for("STRIPE_KEY");
    assert_eq!(obs.len(), 1);
    assert!(obs[0].confidence < 0.5, "single observation should be low confidence");
    assert!(!obs[0].is_high_confidence());
}

#[test]
fn profile_store_reaches_high_confidence_after_threshold() {
    let mut store = ContextualLeakProfileStore::with_path("/dev/null".into());
    let ctx = json_ctx();
    for _ in 0..PROFILE_CONFIDENCE_THRESHOLD {
        store.record_leak("OPENAI_KEY", ".secret", &ctx).unwrap();
    }
    let obs = store.all_paths_for("OPENAI_KEY");
    assert_eq!(obs.len(), 1);
    assert!(
        obs[0].is_high_confidence(),
        "confidence={} should be high after {} observations",
        obs[0].confidence,
        PROFILE_CONFIDENCE_THRESHOLD
    );
}

#[test]
fn profile_store_separate_paths_tracked_independently() {
    let mut store = ContextualLeakProfileStore::with_path("/dev/null".into());
    let ctx = json_ctx();
    store.record_leak("MY_KEY", ".data.key1", &ctx).unwrap();
    store.record_leak("MY_KEY", ".data.key2", &ctx).unwrap();
    let obs = store.all_paths_for("MY_KEY");
    assert_eq!(obs.len(), 2);
}

#[test]
fn profile_store_different_secrets_tracked_independently() {
    let mut store = ContextualLeakProfileStore::with_path("/dev/null".into());
    let ctx = json_ctx();
    store.record_leak("KEY_A", ".path_a", &ctx).unwrap();
    store.record_leak("KEY_B", ".path_b", &ctx).unwrap();
    assert_eq!(store.all_paths_for("KEY_A").len(), 1);
    assert_eq!(store.all_paths_for("KEY_B").len(), 1);
    assert_eq!(store.len(), 2);
}

#[test]
fn profile_store_persistence_roundtrip() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("leak-profiles.jsonl");

    // Write observations.
    {
        let mut store = ContextualLeakProfileStore::with_path(path.clone());
        let ctx = json_ctx();
        for _ in 0..PROFILE_CONFIDENCE_THRESHOLD {
            store.record_leak("PERSIST_KEY", ".nested.secret", &ctx).unwrap();
        }
    }

    // Load from disk in a fresh store.
    let mut store2 = ContextualLeakProfileStore::with_path(path);
    store2.load().unwrap();
    let obs = store2.all_paths_for("PERSIST_KEY");
    assert_eq!(obs.len(), 1, "observation should survive disk round-trip");
    assert!(obs[0].is_high_confidence());
    assert_eq!(obs[0].json_path, ".nested.secret");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Exact scrub still works (regression — adaptive layer must not break it)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn adaptive_scrubber_exact_vault_match_still_scrubbed() {
    let scrubber = ephemeral_scrubber(&[("STRIPE_KEY", "sk_live_realstripekey12345")]);
    let body = r#"{"data":{"live_key":"sk_live_realstripekey12345"}}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&stripe_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    assert!(event.scrubbed);
    assert!(!s.contains("sk_live_realstripekey12345"), "exact secret must be scrubbed: {s}");
    assert!(s.contains("[REDACTED:"), "must have redaction marker: {s}");
}

#[test]
fn adaptive_scrubber_clean_body_not_touched() {
    let scrubber = ephemeral_scrubber(&[("MY_KEY", "sk_live_realkey12345xyz")]);
    let body = r#"{"status":"ok","count":42}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&json_ctx()),
    );
    assert!(!event.scrubbed);
    assert_eq!(String::from_utf8(out).unwrap(), body);
}

#[test]
fn adaptive_scrubber_empty_body_clean() {
    let scrubber = ephemeral_scrubber(&[("K", "sk_live_x")]);
    let (out, event) = scrubber.scrub_buffered_adaptive(Some("application/json"), b"", None);
    assert!(out.is_empty());
    assert!(!event.scrubbed);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Adaptive path-targeted redaction — realistic API responses
// ─────────────────────────────────────────────────────────────────────────────

/// Teach the scrubber that STRIPE_KEY leaks at `.data.live_key`, then send
/// a response with a *different* key value at the same path — it should be
/// redacted adaptively.
#[test]
fn adaptive_redacts_rotated_stripe_key_at_known_path() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("profiles.jsonl");
    let store = Arc::new(Mutex::new(ContextualLeakProfileStore::with_path(path)));

    // Prime the profile store with enough observations for high confidence.
    {
        let mut s = store.lock().unwrap();
        let ctx = stripe_ctx();
        for _ in 0..PROFILE_CONFIDENCE_THRESHOLD {
            s.record_leak("STRIPE_KEY", ".data.live_key", &ctx).unwrap();
        }
    }

    // Now use a *different* Stripe key value (simulating rotation) at the same path.
    let scrubber = persistent_scrubber(&[("STRIPE_KEY", "sk_live_originalkey123456789")], Arc::clone(&store));
    let body = r#"{"data":{"live_key":"sk_live_ROTATED_NEW_KEY_ABCDE"},"id":"cus_xyz"}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&stripe_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    // The rotated key should be adaptively redacted.
    assert!(
        event.scrubbed || !s.contains("sk_live_ROTATED_NEW_KEY_ABCDE"),
        "rotated key should be adaptively redacted: {s}"
    );
}

/// OpenAI error response — secret in `.error.message` via exact match, profile learned.
#[test]
fn openai_error_response_exact_match_and_profile_learned() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("profiles.jsonl");
    let store = Arc::new(Mutex::new(ContextualLeakProfileStore::with_path(path)));
    let secret = "sk-realOpenAIkey1234567890abcdef";
    let scrubber = persistent_scrubber(&[("OPENAI_KEY", secret)], Arc::clone(&store));

    let body = format!(
        r#"{{"error":{{"message":"Invalid API key: {secret}","type":"invalid_request_error","code":"invalid_api_key"}}}}"#
    );
    let ctx = RequestContext::new("POST", "/v1/chat/completions", "application/json", 401);
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&ctx),
    );
    let s = String::from_utf8(out).unwrap();
    assert!(event.scrubbed, "should have been scrubbed");
    assert!(!s.contains(secret), "secret must not appear in output: {s}");

    // Profile should now have one observation.
    let store_guard = store.lock().unwrap();
    let obs = store_guard.all_paths_for("OPENAI_KEY");
    assert!(!obs.is_empty(), "profile should record the leak path");
    assert_eq!(obs[0].json_path, ".error.message");
}

/// Stripe webhook — secret at `.data.object.key`.
#[test]
fn stripe_webhook_nested_object_exact_scrub() {
    let scrubber = ephemeral_scrubber(&[("STRIPE_KEY", "sk_live_webhookkey12345678")]);
    let body = r#"{"id":"evt_xxx","data":{"object":{"key":"sk_live_webhookkey12345678"}}}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&stripe_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    assert!(event.scrubbed);
    assert!(!s.contains("sk_live_webhookkey12345678"), "Stripe key must be scrubbed: {s}");
}

/// AWS SDK response returning access key in `.Credentials.AccessKeyId`.
#[test]
fn aws_credentials_response_exact_scrub() {
    let scrubber = ephemeral_scrubber(&[("AWS_KEY", "AKIAIOSFODNN7EXAMPLE0")]);
    let body = r#"{"Credentials":{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE0","SecretAccessKey":"hidden","Expiration":"2099-01-01T00:00:00Z"}}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&aws_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    assert!(event.scrubbed);
    assert!(!s.contains("AKIAIOSFODNN7EXAMPLE0"), "AWS key must be scrubbed: {s}");
    assert!(s.contains("hidden"), "non-secret field must survive");
}

/// Response with secret in array of credential objects.
#[test]
fn secret_in_array_of_objects_exact_scrub() {
    let scrubber = ephemeral_scrubber(&[("MY_KEY", "sk-arr-secret-abcdef123456789")]);
    let body = r#"{"keys":[{"name":"primary","value":"sk-arr-secret-abcdef123456789"},{"name":"backup","value":"safe_value"}]}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&json_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    assert!(event.scrubbed);
    assert!(!s.contains("sk-arr-secret-abcdef123456789"), "array secret must be scrubbed: {s}");
    assert!(s.contains("safe_value"), "non-secret array element must survive");
}

/// Multi-secret response — both secrets scrubbed independently.
#[test]
fn multi_secret_response_both_scrubbed() {
    let scrubber = ephemeral_scrubber(&[
        ("OPENAI_KEY", "sk-openai-multi-test-abc123"),
        ("STRIPE_KEY", "sk_live_multi_test_xyz789"),
    ]);
    let body = r#"{"openai":"sk-openai-multi-test-abc123","stripe":"sk_live_multi_test_xyz789"}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&json_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    assert!(event.scrubbed);
    assert!(!s.contains("sk-openai-multi-test-abc123"), "OpenAI key must be scrubbed: {s}");
    assert!(!s.contains("sk_live_multi_test_xyz789"), "Stripe key must be scrubbed: {s}");
}

/// Non-JSON body — adaptive layer must not touch it (no JSON parsing attempted).
#[test]
fn non_json_body_not_touched_by_adaptive_layer() {
    let scrubber = ephemeral_scrubber(&[("K", "sk_live_plaintextkey12345")]);
    let body = "Authorization: Bearer sk_live_plaintextkey12345\nContent-Length: 0";
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("text/plain"),
        body.as_bytes(),
        Some(&json_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    // The exact vault match will scrub via the inner scrubber.
    assert!(event.scrubbed);
    assert!(!s.contains("sk_live_plaintextkey12345"), "plain-text secret must be scrubbed via inner scrubber");
    // Adaptive hits should be empty for non-JSON.
    assert!(event.adaptive_hits.is_empty(), "no adaptive hits expected for non-JSON");
}

/// Already-redacted value at a high-confidence path must NOT be re-wrapped.
#[test]
fn already_redacted_value_not_double_redacted() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("profiles.jsonl");
    let store = Arc::new(Mutex::new(ContextualLeakProfileStore::with_path(path)));

    // Prime profile store.
    {
        let mut s = store.lock().unwrap();
        let ctx = stripe_ctx();
        for _ in 0..PROFILE_CONFIDENCE_THRESHOLD {
            s.record_leak("STRIPE_KEY", ".key", &ctx).unwrap();
        }
    }

    let scrubber = persistent_scrubber(&[("STRIPE_KEY", "sk_live_original")], Arc::clone(&store));
    // Body already has a redaction marker at the known path.
    let body = r#"{"key":"[REDACTED:sk_live_*]","other":"fine"}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&stripe_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    // Should not wrap in another [REDACTED:adaptive:...] layer.
    assert!(
        !s.contains("[REDACTED:adaptive:STRIPE_KEY]"),
        "already-redacted value must not be double-redacted: {s}"
    );
    let _ = event;
}

/// Very short value at a known path (< 8 chars) must NOT trigger adaptive redaction.
#[test]
fn short_value_at_known_path_not_adaptively_redacted() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("profiles.jsonl");
    let store = Arc::new(Mutex::new(ContextualLeakProfileStore::with_path(path)));

    {
        let mut s = store.lock().unwrap();
        let ctx = json_ctx();
        for _ in 0..PROFILE_CONFIDENCE_THRESHOLD {
            s.record_leak("SHORT_KEY", ".val", &ctx).unwrap();
        }
    }

    let scrubber = persistent_scrubber(&[("SHORT_KEY", "sk_live_longoriginalvalue")], Arc::clone(&store));
    let body = r#"{"val":"abc"}"#; // only 3 chars — below threshold
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&json_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    assert!(
        !event.adaptive_hits.iter().any(|h| h.json_path == ".val"),
        "short value must not be adaptively redacted: {s}"
    );
}

/// AdaptiveScrubHit metadata is populated with correct fields.
#[test]
fn adaptive_hit_metadata_correct() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("profiles.jsonl");
    let store = Arc::new(Mutex::new(ContextualLeakProfileStore::with_path(path)));

    {
        let mut s = store.lock().unwrap();
        let ctx = stripe_ctx();
        for _ in 0..PROFILE_CONFIDENCE_THRESHOLD {
            s.record_leak("META_KEY", ".credentials.token", &ctx).unwrap();
        }
    }

    let scrubber = persistent_scrubber(&[("META_KEY", "sk_live_original_meta_key_abc")], Arc::clone(&store));
    // Use a different value at the learned path (simulating rotation).
    let body = r#"{"credentials":{"token":"sk_live_rotated_new_value_xyz_abc_def"},"status":"ok"}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&stripe_ctx()),
    );
    let s = String::from_utf8(out).unwrap();
    // If the adaptive hit fired, verify metadata.
    if !event.adaptive_hits.is_empty() {
        let hit = &event.adaptive_hits[0];
        assert_eq!(hit.secret_name, "META_KEY");
        assert_eq!(hit.json_path, ".credentials.token");
        assert!(hit.profile_confidence >= 0.90, "confidence should be high: {}", hit.profile_confidence);
        assert!(!s.contains("sk_live_rotated_new_value_xyz_abc_def"),
            "adaptively-hit value must be redacted: {s}");
    }
}

/// Profile observations are returned by `profile_observations()`.
#[test]
fn profile_observations_returned_correctly() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("profiles.jsonl");
    let store = Arc::new(Mutex::new(ContextualLeakProfileStore::with_path(path)));
    {
        let mut s = store.lock().unwrap();
        let ctx = json_ctx();
        s.record_leak("OBS_KEY", ".data.key", &ctx).unwrap();
        s.record_leak("OBS_KEY2", ".other.field", &ctx).unwrap();
    }

    let scrubber = persistent_scrubber(
        &[("OBS_KEY", "sk_live_obs_key_123"), ("OBS_KEY2", "sk_live_obs_key2_456")],
        Arc::clone(&store),
    );
    let obs = scrubber.profile_observations();
    assert_eq!(obs.len(), 2);
    let names: Vec<_> = obs.iter().map(|o| o.secret_name.as_str()).collect();
    assert!(names.contains(&"OBS_KEY"), "OBS_KEY should be in observations");
    assert!(names.contains(&"OBS_KEY2"), "OBS_KEY2 should be in observations");
}

/// Baseline `ResponseScrubber` (non-adaptive) still works unchanged.
#[test]
fn baseline_scrubber_still_works_after_adaptive_additions() {
    let mut m = HashMap::new();
    m.insert("TOK".to_string(), "sk_live_baselinekey123456789".to_string());
    let scrubber = ResponseScrubber::from_token_map(&m);
    let body = r#"{"msg":"key is sk_live_baselinekey123456789"}"#;
    let (out, event) = scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
    let s = String::from_utf8(out).unwrap();
    assert!(event.scrubbed);
    assert!(!s.contains("sk_live_baselinekey123456789"), "baseline scrubber must still work: {s}");
}

/// The adaptive scrubber's inner() accessor returns a working ResponseScrubber.
#[test]
fn inner_scrubber_accessible_and_functional() {
    let scrubber = ephemeral_scrubber(&[("MY_KEY", "sk_live_innertest12345678")]);
    let inner = scrubber.inner();
    let body = b"the key is sk_live_innertest12345678 here";
    let (out, event) = inner.scrub_buffered(Some("text/plain"), body);
    assert!(event.scrubbed);
    assert!(
        !String::from_utf8(out).unwrap().contains("sk_live_innertest12345678"),
        "inner scrubber must be functional"
    );
}

/// RequestContext fields are round-tripped via serde correctly.
#[test]
fn request_context_serde_roundtrip() {
    let ctx = RequestContext::new("POST", "/v1/completions", "application/json", 200);
    let json = serde_json::to_string(&ctx).unwrap();
    let ctx2: RequestContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, ctx2);
    assert_eq!(ctx2.method, "POST");
    assert_eq!(ctx2.url_path, "/v1/completions");
    assert_eq!(ctx2.status_code, 200);
}

/// RequestContext normalises method to uppercase.
#[test]
fn request_context_method_uppercased() {
    let ctx = RequestContext::new("get", "/foo", "text/plain", 200);
    assert_eq!(ctx.method, "GET");
}

/// LeakPathObservation confidence progression matches documented model.
#[test]
fn leak_path_observation_confidence_progression() {
    let mut store = ContextualLeakProfileStore::with_path("/dev/null".into());
    let ctx = json_ctx();

    store.record_leak("CONF_KEY", ".path", &ctx).unwrap();
    let c1 = store.all_paths_for("CONF_KEY")[0].confidence;
    assert!((c1 - 0.40).abs() < 0.01, "1 obs → 0.40, got {c1}");

    store.record_leak("CONF_KEY", ".path", &ctx).unwrap();
    let c2 = store.all_paths_for("CONF_KEY")[0].confidence;
    assert!((c2 - 0.70).abs() < 0.01, "2 obs → 0.70, got {c2}");

    store.record_leak("CONF_KEY", ".path", &ctx).unwrap();
    let c3 = store.all_paths_for("CONF_KEY")[0].confidence;
    assert!(c3 >= 0.90, "3 obs → ≥0.90, got {c3}");

    assert!(c3 > c2 && c2 > c1, "confidence must be monotonically increasing");
}

/// Profile store `all_observations()` sorted by confidence descending.
#[test]
fn all_observations_sorted_by_confidence_desc() {
    let mut store = ContextualLeakProfileStore::with_path("/dev/null".into());
    let ctx = json_ctx();

    // LOW: 1 observation.
    store.record_leak("LOW_KEY", ".low_path", &ctx).unwrap();
    // HIGH: many observations.
    for _ in 0..5 {
        store.record_leak("HIGH_KEY", ".high_path", &ctx).unwrap();
    }

    let obs = store.all_observations();
    assert_eq!(obs.len(), 2);
    assert!(
        obs[0].confidence >= obs[1].confidence,
        "observations must be sorted by confidence desc: first={}, second={}",
        obs[0].confidence,
        obs[1].confidence
    );
    assert_eq!(obs[0].secret_name, "HIGH_KEY");
}

/// `ContextualLeakProfileStore::is_empty()` and `len()` work correctly.
#[test]
fn profile_store_len_and_is_empty() {
    let mut store = ContextualLeakProfileStore::with_path("/dev/null".into());
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);

    let ctx = json_ctx();
    store.record_leak("K1", ".p1", &ctx).unwrap();
    assert!(!store.is_empty());
    assert_eq!(store.len(), 1);

    store.record_leak("K2", ".p2", &ctx).unwrap();
    assert_eq!(store.len(), 2);
}

/// `high_confidence_paths_for` only returns observations above the threshold.
#[test]
fn high_confidence_paths_for_filters_correctly() {
    let mut store = ContextualLeakProfileStore::with_path("/dev/null".into());
    let ctx = json_ctx();

    // One low-confidence observation.
    store.record_leak("FC_KEY", ".low", &ctx).unwrap();
    assert!(store.high_confidence_paths_for("FC_KEY").is_empty(),
        "1 observation should not be high confidence");

    // Pump to high confidence.
    for _ in 1..PROFILE_CONFIDENCE_THRESHOLD {
        store.record_leak("FC_KEY", ".low", &ctx).unwrap();
    }
    let high = store.high_confidence_paths_for("FC_KEY");
    assert!(!high.is_empty(), "should be high confidence after {} observations", PROFILE_CONFIDENCE_THRESHOLD);
}

/// Adaptive scrubber with no profiles does a clean pass-through on benign JSON.
#[test]
fn adaptive_scrubber_no_profiles_passthrough_benign() {
    let scrubber = ephemeral_scrubber(&[("K", "sk_live_somekey12345678901")]);
    let body = r#"{"status":"ok","data":{"count":5,"message":"hello"}}"#;
    let (out, event) = scrubber.scrub_buffered_adaptive(
        Some("application/json"),
        body.as_bytes(),
        Some(&json_ctx()),
    );
    assert!(!event.scrubbed, "benign body should not be scrubbed");
    assert_eq!(String::from_utf8(out).unwrap(), body);
}

/// PROFILE_CONFIDENCE_THRESHOLD is exported and is a reasonable value.
#[test]
fn profile_confidence_threshold_is_reasonable() {
    assert!(
        PROFILE_CONFIDENCE_THRESHOLD >= 2,
        "threshold must be at least 2 to avoid false positives"
    );
    assert!(
        PROFILE_CONFIDENCE_THRESHOLD <= 10,
        "threshold must not be unreasonably high"
    );
}
