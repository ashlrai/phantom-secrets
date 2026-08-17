//! Integration tests: proxy response scrubbing edge cases for body_scope.rs.
//!
//! Covers:
//! 1. Streaming JSON edge cases — tokens at frame boundaries, nested objects,
//!    array values, escaped strings.
//! 2. Malformed JSON recovery — incomplete JSON, truncated tokens, invalid
//!    UTF-8 recovery.
//! 3. Content-type ambiguity — charset suffixes, multipart boundaries,
//!    base64-encoded payloads.
//! 4. Scoped replacement verification — tokens NOT replaced in `prompt`,
//!    `content`, `message`, `body` fields; ARE replaced in `authorization`
//!    headers and configured service headers.
//!
//! Run with:
//!   cargo test --package phantom-secrets-proxy --test body_scope_edge_cases -- --test-threads=1

use phantom_proxy::body_scope::{
    is_allowed_header, scoped_body_replace, should_stream_replace, stream_replace_flush,
    stream_replace_frame, PHM_TOKEN_LEN, PHM_TOKEN_MAX_PARTIAL,
};
use phantom_proxy::Interceptor;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A valid 68-byte phantom token (4 prefix + 64 lowercase hex chars).
const PHM: &str = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
const REAL: &str = "sk-real-openai-key-abcdef";

/// A second token/secret pair for multi-token tests.
const PHM2: &str = "phm_1111222233334444555566667777888899990000aaaabbbbccccddddeeee0000";
const REAL2: &str = "sk-ant-real-anthropic-99999";

fn interceptor() -> Interceptor {
    let mut m = HashMap::new();
    m.insert(PHM.to_string(), REAL.to_string());
    Interceptor::new(m)
}

fn dual_interceptor() -> Interceptor {
    let mut m = HashMap::new();
    m.insert(PHM.to_string(), REAL.to_string());
    m.insert(PHM2.to_string(), REAL2.to_string());
    Interceptor::new(m)
}

/// Run `stream_replace_frame` + `stream_replace_flush` over an arbitrary
/// sequence of frames and return the reassembled output as a String.
fn stream_frames(iceptor: &Interceptor, frames: &[&[u8]]) -> String {
    let mut carry = Vec::new();
    let mut out: Vec<u8> = Vec::new();
    for frame in frames {
        let ready = stream_replace_frame(iceptor, &mut carry, frame);
        out.extend_from_slice(&ready);
    }
    let flushed = stream_replace_flush(iceptor, carry);
    out.extend_from_slice(&flushed);
    String::from_utf8(out).expect("output must be valid UTF-8")
}

// ============================================================================
// 1. STREAMING JSON EDGE CASES
// ============================================================================

/// Token split at every possible byte boundary within a plain-text body.
#[test]
fn streaming_token_split_at_every_boundary() {
    let iceptor = interceptor();
    for split in 1..PHM.len() {
        let part1 = PHM.as_bytes()[..split].to_vec();
        let part2 = PHM.as_bytes()[split..].to_vec();
        let result = stream_frames(&iceptor, &[&part1, &part2]);
        assert!(
            result.contains(REAL),
            "real secret missing at split={split}: {result}"
        );
        assert!(
            !result.contains("phm_"),
            "phantom token present at split={split}: {result}"
        );
    }
}

/// Token straddling a three-way frame split.
#[test]
fn streaming_token_three_frame_split() {
    let iceptor = interceptor();
    // Split the token into thirds
    let a = PHM.len() / 3;
    let b = 2 * PHM.len() / 3;
    let p1 = PHM.as_bytes()[..a].to_vec();
    let p2 = PHM.as_bytes()[a..b].to_vec();
    let p3 = PHM.as_bytes()[b..].to_vec();
    let result = stream_frames(&iceptor, &[&p1, &p2, &p3]);
    assert!(result.contains(REAL), "real secret missing: {result}");
    assert!(!result.contains("phm_"), "phantom token present: {result}");
}

/// Token spanning a frame with surrounding content.
#[test]
fn streaming_token_with_surrounding_content() {
    let iceptor = interceptor();
    let prefix = "data: {\"key\": \"";
    let suffix = "\", \"model\": \"gpt-4\"}";
    let full = format!("{prefix}{PHM}{suffix}");
    // Split inside the token
    let split = prefix.len() + 10;
    let p1 = full.as_bytes()[..split].to_vec();
    let p2 = full.as_bytes()[split..].to_vec();
    let result = stream_frames(&iceptor, &[&p1, &p2]);
    assert!(result.contains(REAL), "real secret missing: {result}");
    assert!(
        !result.contains("phm_"),
        "phantom token still present: {result}"
    );
    assert!(
        result.contains(suffix.trim_start_matches(PHM)),
        "suffix lost"
    );
}

/// Multiple tokens in one stream, each potentially at frame boundaries.
#[test]
fn streaming_two_tokens_in_same_stream() {
    let iceptor = dual_interceptor();
    let body = format!("key1={PHM}&key2={PHM2}");
    // Split right between the two tokens
    let split = format!("key1={PHM}&key2=").len() + 5; // into PHM2
    let p1 = body.as_bytes()[..split].to_vec();
    let p2 = body.as_bytes()[split..].to_vec();
    let result = stream_frames(&iceptor, &[&p1, &p2]);
    assert!(result.contains(REAL), "REAL missing: {result}");
    assert!(result.contains(REAL2), "REAL2 missing: {result}");
    assert!(!result.contains("phm_"), "phantom token present: {result}");
}

/// Token entirely in the carry (short first frame, no output until flush).
#[test]
fn streaming_token_entirely_in_carry() {
    let iceptor = interceptor();
    // First frame is shorter than PHM_TOKEN_MAX_PARTIAL — everything stays in carry
    let p1 = PHM.as_bytes()[..5].to_vec();
    let p2 = PHM.as_bytes()[5..].to_vec();
    let mut carry = Vec::new();
    let ready1 = stream_replace_frame(&iceptor, &mut carry, &p1);
    // ready1 must be empty since combined < PHM_TOKEN_MAX_PARTIAL
    assert!(
        ready1.is_empty(),
        "expected nothing emitted on short first frame"
    );
    let ready2 = stream_replace_frame(&iceptor, &mut carry, &p2);
    let flushed = stream_replace_flush(&iceptor, carry);
    let result = String::from_utf8([ready2, flushed].concat()).unwrap();
    assert!(result.contains(REAL), "real secret missing: {result}");
}

/// Single large frame containing the token — no split.
#[test]
fn streaming_whole_token_single_frame() {
    let iceptor = interceptor();
    let body = format!("Authorization: Bearer {PHM}\r\nContent-Type: text/plain");
    let result = stream_frames(&iceptor, &[body.as_bytes()]);
    assert!(result.contains(REAL), "real secret missing: {result}");
    assert!(!result.contains("phm_"), "phantom token present: {result}");
}

/// Empty frames interspersed with the actual token.
#[test]
fn streaming_empty_frames_interspersed() {
    let iceptor = interceptor();
    let p1 = b"prefix-".to_vec();
    let empty = b"".to_vec();
    let p2 = PHM.as_bytes().to_vec();
    let p3 = b"-suffix".to_vec();
    let result = stream_frames(&iceptor, &[&p1, &empty, &p2, &empty, &p3]);
    assert!(result.contains(REAL), "real secret missing: {result}");
    assert!(!result.contains("phm_"), "phantom token present: {result}");
}

/// Nested JSON object with an allowed field several levels deep.
#[test]
fn scoped_json_nested_deep_allowed_field_replaced() {
    let body = format!(r#"{{"level1":{{"level2":{{"level3":{{"api_key":"{PHM}"}}}}}}}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(did, "expected replacement");
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains(REAL), "real secret missing: {s}");
    assert!(!s.contains("phm_"), "phantom token present: {s}");
}

/// JSON array containing allowed-field objects — all entries replaced.
#[test]
fn scoped_json_array_of_objects_with_allowed_fields() {
    let body = format!(r#"[{{"api_key":"{PHM}"}},{{"token":"{PHM2}"}}]"#);
    let (out, did) = scoped_body_replace(
        &dual_interceptor(),
        Some("application/json"),
        body.as_bytes(),
    );
    assert!(did, "expected replacement");
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains(REAL), "REAL missing: {s}");
    assert!(s.contains(REAL2), "REAL2 missing: {s}");
    assert!(!s.contains("phm_"), "phantom token present: {s}");
}

/// JSON with escaped-string values in allowed fields.
#[test]
fn scoped_json_escaped_string_in_allowed_field() {
    // The phantom token itself is pure hex — no escaping needed, but the
    // surrounding string has escape sequences that the parser must handle.
    let body = format!(r#"{{"api_key":"{PHM}","note":"line1\\nline2"}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(did, "expected replacement");
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains(REAL), "real secret missing: {s}");
}

/// Token in JSON sibling field that is NOT allowed — sibling replaced, rest not.
#[test]
fn scoped_json_sibling_field_not_replaced() {
    let body = format!(r#"{{"api_key":"{PHM}","prompt":"User said {PHM}"}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(did, "expected api_key to be replaced");
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains(REAL), "api_key replacement missing: {s}");
    // prompt must still contain the raw phantom token
    assert!(
        s.contains(PHM),
        "prompt phantom token was wrongly scrubbed: {s}"
    );
}

// ============================================================================
// 2. MALFORMED JSON RECOVERY
// ============================================================================

/// Incomplete JSON (missing closing brace) — passes through unchanged.
#[test]
fn malformed_json_missing_close_brace() {
    let body = format!(r#"{{"api_key":"{PHM}""#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(!did, "must not replace in malformed JSON");
    assert_eq!(out, body.as_bytes(), "body must be unchanged");
}

/// Truncated token mid-string — malformed JSON, passes through.
#[test]
fn malformed_json_truncated_token_mid_string() {
    // Token is valid hex but string is not closed
    let partial_token = &PHM[..30];
    let body = format!(r#"{{"api_key":"{partial_token}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(!did);
    assert_eq!(out, body.as_bytes());
}

/// Completely invalid JSON string — passes through unchanged, no panic.
#[test]
fn malformed_json_completely_invalid() {
    let body = b"not json at all { garbage [[[";
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body);
    assert!(!did);
    assert_eq!(out.as_slice(), body);
}

/// JSON with a null value in an allowed field — no substitution, no panic.
#[test]
fn malformed_json_null_in_allowed_field() {
    let body = br#"{"api_key": null}"#;
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body);
    assert!(!did);
    assert_eq!(out.as_slice(), body);
}

/// JSON with a numeric value in an allowed field — no panic.
#[test]
fn malformed_json_numeric_in_allowed_field() {
    let body = br#"{"api_key": 12345}"#;
    let (_out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body);
    assert!(!did);
}

/// Invalid UTF-8 bytes — body passed through unchanged without panic.
#[test]
fn malformed_invalid_utf8_in_non_json_body() {
    // Non-JSON content-type; body contains invalid UTF-8
    let body: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x41]; // invalid UTF-8 prefix
    let (out, did) = scoped_body_replace(&interceptor(), Some("text/plain"), &body);
    assert!(!did, "must not attempt replacement on non-JSON");
    assert_eq!(out, body);
}

/// Trailing comma in JSON (invalid JSON in strict mode) — passes through.
#[test]
fn malformed_json_trailing_comma() {
    let body = format!(r#"{{"api_key":"{PHM}",}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    // serde_json rejects trailing commas; body must be passed through
    assert!(!did);
    assert_eq!(out, body.as_bytes());
}

/// Empty JSON body `{}` — no replacement, no panic.
#[test]
fn malformed_json_empty_object() {
    let body = b"{}";
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body);
    assert!(!did);
    assert_eq!(out.as_slice(), body);
}

// ============================================================================
// 3. CONTENT-TYPE AMBIGUITY
// ============================================================================

/// `application/json` with charset= suffix still triggers JSON path.
#[test]
fn content_type_json_with_charset_utf8() {
    let body = format!(r#"{{"api_key":"{PHM}"}}"#);
    let (out, did) = scoped_body_replace(
        &interceptor(),
        Some("application/json; charset=utf-8"),
        body.as_bytes(),
    );
    assert!(did);
    assert!(std::str::from_utf8(&out).unwrap().contains(REAL));
}

/// `application/json` with extra whitespace in content-type.
#[test]
fn content_type_json_with_whitespace_params() {
    let body = format!(r#"{{"token":"{PHM}"}}"#);
    let (out, did) = scoped_body_replace(
        &interceptor(),
        Some("application/json ;  charset=utf-8"),
        body.as_bytes(),
    );
    assert!(did);
    assert!(std::str::from_utf8(&out).unwrap().contains(REAL));
}

/// `application/vnd.api+json` (JSON-API) triggers the JSON path.
#[test]
fn content_type_vendor_plus_json() {
    let body = format!(r#"{{"api_key":"{PHM}"}}"#);
    let (out, did) = scoped_body_replace(
        &interceptor(),
        Some("application/vnd.api+json"),
        body.as_bytes(),
    );
    assert!(did);
    assert!(std::str::from_utf8(&out).unwrap().contains(REAL));
}

/// `multipart/form-data` is NOT JSON — body passed through unchanged.
#[test]
fn content_type_multipart_not_replaced() {
    let body = format!(
        "--boundary\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{PHM}\r\n--boundary--"
    );
    let (out, did) = scoped_body_replace(
        &interceptor(),
        Some("multipart/form-data; boundary=boundary"),
        body.as_bytes(),
    );
    assert!(!did, "multipart must not be treated as JSON");
    assert_eq!(out, body.as_bytes());
}

/// `application/x-www-form-urlencoded` is not replaced by scoped_body_replace
/// (the streaming path handles it).
#[test]
fn content_type_form_urlencoded_not_replaced_by_scoped() {
    let body = format!("client_secret={PHM}&grant_type=client_credentials");
    let (out, did) = scoped_body_replace(
        &interceptor(),
        Some("application/x-www-form-urlencoded"),
        body.as_bytes(),
    );
    assert!(!did);
    assert_eq!(out, body.as_bytes());
}

/// `application/x-www-form-urlencoded` IS replaced by stream path.
#[test]
fn content_type_form_urlencoded_replaced_via_stream() {
    let iceptor = interceptor();
    let body = format!("client_secret={PHM}&grant_type=client_credentials");
    let result = stream_frames(&iceptor, &[body.as_bytes()]);
    assert!(result.contains(REAL), "real secret missing: {result}");
    assert!(!result.contains("phm_"), "phantom token present: {result}");
}

/// Base64-encoded payload in a non-JSON body — not decoded, not replaced.
#[test]
fn content_type_base64_payload_not_decoded() {
    // Base64-encode a JSON blob that contains the phantom token; the proxy
    // must NOT decode-and-inspect it.
    let json = format!(r#"{{"api_key":"{PHM}"}}"#);
    let encoded = base64_encode(json.as_bytes());
    let (out, did) = scoped_body_replace(
        &interceptor(),
        Some("application/octet-stream"),
        encoded.as_bytes(),
    );
    assert!(!did, "base64 payload must not be decoded/replaced");
    assert_eq!(out, encoded.as_bytes());
}

/// Absent content-type — body passed through unchanged.
#[test]
fn content_type_absent_body_unchanged() {
    let body = format!("secret={PHM}");
    let (out, did) = scoped_body_replace(&interceptor(), None, body.as_bytes());
    assert!(!did);
    assert_eq!(out, body.as_bytes());
}

/// Unknown/custom content-type — body passed through unchanged.
#[test]
fn content_type_unknown_body_unchanged() {
    let body = format!("key={PHM}");
    let (out, did) = scoped_body_replace(
        &interceptor(),
        Some("application/x-custom-format"),
        body.as_bytes(),
    );
    assert!(!did);
    assert_eq!(out, body.as_bytes());
}

/// `should_stream_replace` returns false for JSON content types (buffered path).
#[test]
fn should_stream_replace_json_excluded() {
    assert!(!should_stream_replace(Some("application/json")));
    assert!(!should_stream_replace(Some(
        "application/json; charset=utf-8"
    )));
    assert!(!should_stream_replace(Some("application/vnd.api+json")));
}

/// `should_stream_replace` returns true for text/* types.
#[test]
fn should_stream_replace_text_types() {
    assert!(should_stream_replace(Some("text/plain")));
    assert!(should_stream_replace(Some("text/event-stream")));
    assert!(should_stream_replace(Some("text/html")));
    assert!(should_stream_replace(Some("text/plain; charset=utf-8")));
}

/// `should_stream_replace` returns true for form-urlencoded.
#[test]
fn should_stream_replace_form_urlencoded() {
    assert!(should_stream_replace(Some(
        "application/x-www-form-urlencoded"
    )));
}

/// `should_stream_replace` returns false for binary and multipart.
#[test]
fn should_stream_replace_binary_false() {
    assert!(!should_stream_replace(Some("application/octet-stream")));
    assert!(!should_stream_replace(Some("image/png")));
    assert!(!should_stream_replace(Some("multipart/form-data")));
    assert!(!should_stream_replace(None));
    assert!(!should_stream_replace(Some("")));
}

// ============================================================================
// 4. SCOPED REPLACEMENT VERIFICATION
// ============================================================================

/// Tokens in `prompt` field must NOT be replaced.
#[test]
fn scoped_prompt_field_not_replaced() {
    let body = format!(r#"{{"prompt":"The key is {PHM}","model":"gpt-4"}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(!did);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(
        s.contains(PHM),
        "phantom token wrongly scrubbed from prompt"
    );
    assert!(!s.contains(REAL), "real secret leaked into prompt");
}

/// Tokens in `content` field (message content) must NOT be replaced.
#[test]
fn scoped_content_field_not_replaced() {
    let body = format!(r#"{{"messages":[{{"role":"user","content":"My key is {PHM}"}}]}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(!did);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(
        s.contains(PHM),
        "phantom token wrongly scrubbed from content"
    );
    assert!(!s.contains(REAL));
}

/// Tokens in `message` field must NOT be replaced.
#[test]
fn scoped_message_field_not_replaced() {
    let body = format!(r#"{{"message":"Error with key {PHM}"}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(!did);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains(PHM));
    assert!(!s.contains(REAL));
}

/// Tokens in `body` field must NOT be replaced.
#[test]
fn scoped_body_field_not_replaced() {
    let body = format!(r#"{{"body":"Request body contained {PHM}"}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(!did);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains(PHM));
    assert!(!s.contains(REAL));
}

/// Tokens in `text` field must NOT be replaced.
#[test]
fn scoped_text_field_not_replaced() {
    let body = format!(r#"{{"text":"Mention of {PHM} in text"}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(!did);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains(PHM));
}

/// Mixed body: `api_key` replaced, `prompt` not replaced, in same object.
#[test]
fn scoped_mixed_allowed_and_disallowed_fields() {
    let body = format!(r#"{{"api_key":"{PHM}","prompt":"User typed {PHM}","model":"gpt-4"}}"#);
    let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
    assert!(did, "api_key must be replaced");
    let s = std::str::from_utf8(&out).unwrap();
    // api_key got replaced
    assert!(s.contains(REAL), "api_key replacement missing: {s}");
    // prompt still has the raw phantom token
    assert!(s.contains(PHM), "prompt was wrongly scrubbed: {s}");
}

/// `authorization` header IS in the default allowed list.
#[test]
fn scoped_authorization_header_allowed() {
    assert!(is_allowed_header("authorization", ""));
    assert!(is_allowed_header("Authorization", ""));
    assert!(is_allowed_header("AUTHORIZATION", ""));
}

/// `x-api-key` header IS in the default allowed list.
#[test]
fn scoped_x_api_key_header_allowed() {
    assert!(is_allowed_header("x-api-key", ""));
    assert!(is_allowed_header("X-API-Key", ""));
    assert!(is_allowed_header("X-Api-Key", ""));
}

/// Per-service configured header IS allowed when provided.
#[test]
fn scoped_service_header_allowed() {
    assert!(is_allowed_header("x-my-service-key", "x-my-service-key"));
    assert!(is_allowed_header("X-My-Service-Key", "x-my-service-key"));
    assert!(is_allowed_header("x-my-service-key", "X-MY-SERVICE-KEY"));
}

/// Non-auth headers (User-Agent, Content-Type, etc.) are NOT allowed.
#[test]
fn scoped_non_auth_headers_not_allowed() {
    assert!(!is_allowed_header("user-agent", ""));
    assert!(!is_allowed_header("content-type", ""));
    assert!(!is_allowed_header("accept", ""));
    assert!(!is_allowed_header("host", ""));
    assert!(!is_allowed_header("x-request-id", ""));
    assert!(!is_allowed_header("x-trace-id", ""));
}

/// Service header mismatch — different service header name is not allowed.
#[test]
fn scoped_service_header_mismatch_not_allowed() {
    assert!(!is_allowed_header("x-other-header", "x-my-service-key"));
    assert!(!is_allowed_header("x-my-service-key", ""));
}

/// `proxy-authorization` IS in the default allowed list.
#[test]
fn scoped_proxy_authorization_allowed() {
    assert!(is_allowed_header("proxy-authorization", ""));
    assert!(is_allowed_header("Proxy-Authorization", ""));
}

/// `cookie` IS in the default allowed list (session tokens).
#[test]
fn scoped_cookie_header_allowed() {
    assert!(is_allowed_header("cookie", ""));
    assert!(is_allowed_header("Cookie", ""));
}

// ============================================================================
// 5. TOKEN LENGTH & BOUNDARY CONSTANTS
// ============================================================================

/// PHM_TOKEN_LEN must equal 68 (4 prefix + 64 hex chars).
#[test]
fn token_len_constant_correct() {
    assert_eq!(PHM_TOKEN_LEN, 68);
    assert_eq!(PHM.len(), PHM_TOKEN_LEN, "test token must match constant");
}

/// PHM_TOKEN_MAX_PARTIAL must be PHM_TOKEN_LEN - 1.
#[test]
fn token_max_partial_constant_correct() {
    assert_eq!(PHM_TOKEN_MAX_PARTIAL, PHM_TOKEN_LEN - 1);
}

/// After each streaming call, `carry` must never exceed PHM_TOKEN_MAX_PARTIAL.
#[test]
fn streaming_carry_never_exceeds_max_partial() {
    let iceptor = interceptor();
    let body = format!("prefix {PHM} middle {PHM} suffix");
    let frames: Vec<&[u8]> = body.as_bytes().chunks(15).collect();
    let mut carry = Vec::new();
    for frame in &frames {
        let _ = stream_replace_frame(&iceptor, &mut carry, frame);
        assert!(
            carry.len() <= PHM_TOKEN_MAX_PARTIAL,
            "carry exceeds max_partial: len={} frame={:?}",
            carry.len(),
            std::str::from_utf8(frame).unwrap_or("<binary>")
        );
    }
}

// ============================================================================
// Helper (minimal base64 encode for test use only)
// ============================================================================

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 2 < input.len() {
        let b0 = input[i] as usize;
        let b1 = input[i + 1] as usize;
        let b2 = input[i + 2] as usize;
        out.push(CHARS[b0 >> 2] as char);
        out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        out.push(CHARS[((b1 & 0xF) << 2) | (b2 >> 6)] as char);
        out.push(CHARS[b2 & 0x3F] as char);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let b0 = input[i] as usize;
            out.push(CHARS[b0 >> 2] as char);
            out.push(CHARS[(b0 & 3) << 4] as char);
            out.push_str("==");
        }
        2 => {
            let b0 = input[i] as usize;
            let b1 = input[i + 1] as usize;
            out.push(CHARS[b0 >> 2] as char);
            out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
            out.push(CHARS[(b1 & 0xF) << 2] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}
