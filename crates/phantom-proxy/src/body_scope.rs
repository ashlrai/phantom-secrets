//! Scope control for phantom-token substitution in outbound requests.
//!
//! Blind string-replace across an entire request body is a defense-in-depth
//! violation (F9): any `phm_...` substring a user types into a chat message
//! body would be rewritten to the real secret before the upstream ever sees
//! it. This module restricts substitution to:
//!
//! - A whitelist of auth-bearing request header names, plus the per-service
//!   configured header (e.g. `Authorization`, `x-api-key`).
//! - For `application/json` bodies: a whitelist of known-secret-bearing JSON
//!   field names, matched at any depth.
//! - For `application/x-www-form-urlencoded` bodies: the same whitelist,
//!   applied to exact form-field names without decoding or normalizing the
//!   rest of the payload.
//!
//! Anywhere else, if a phm-token is present, we log a warning and pass the
//! body through unchanged — so a misconfigured client fails loudly instead
//! of silently leaking a substituted secret to an unexpected field.

use crate::interceptor::Interceptor;
use tracing::{debug, warn};

/// Request header names (lowercase) where phm-token substitution is allowed.
/// The per-route configured header (`ServiceRoute.header`) is also allowed
/// on top of this list.
const DEFAULT_ALLOWED_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "cookie",
];

/// JSON field names (lowercase) where substitution is allowed inside
/// `application/json` request bodies. Matched at any depth.
const DEFAULT_ALLOWED_JSON_FIELDS: &[&str] = &[
    "api_key",
    "apikey",
    "key",
    "token",
    "access_token",
    "auth_token",
    "authorization",
    "client_secret",
    "secret",
    "password",
];

/// Returns true if `name` is a header where phm-token substitution is
/// permitted. `service_header` is the per-route configured header name
/// (may be empty for non-routed paths).
pub fn is_allowed_header(name: &str, service_header: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if DEFAULT_ALLOWED_HEADERS.iter().any(|h| *h == lower) {
        return true;
    }
    !service_header.is_empty() && service_header.eq_ignore_ascii_case(&lower)
}

fn is_allowed_json_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    DEFAULT_ALLOWED_JSON_FIELDS.iter().any(|f| *f == lower)
}

fn is_json_content_type(ct: &str) -> bool {
    let lower = ct.to_ascii_lowercase();
    // "application/json", "application/json; charset=utf-8",
    // "application/vnd.api+json", etc.
    if let Some(mime) = lower.split(';').next() {
        let mime = mime.trim();
        mime == "application/json" || (mime.starts_with("application/") && mime.ends_with("+json"))
    } else {
        false
    }
}

fn is_form_content_type(ct: &str) -> bool {
    ct.split(';')
        .next()
        .map(str::trim)
        .is_some_and(|mime| mime.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

/// Phantom token format: `phm_` prefix + 64 lowercase hex chars = 68 bytes.
/// When streaming, a token can straddle a frame boundary; we carry at most
/// `PHM_TOKEN_MAX_PARTIAL` bytes from the tail of one frame into the next.
pub const PHM_TOKEN_LEN: usize = 68; // "phm_" (4) + 64 hex chars
pub const PHM_TOKEN_MAX_PARTIAL: usize = PHM_TOKEN_LEN - 1; // 67 bytes

/// Returns true for content-types where safe streaming token replacement is
/// possible without a full body buffer.
///
/// Streaming is allowed for:
/// - `text/*`                              (plain text, event-stream, etc.)
///
/// `application/json` is intentionally excluded. The JSON path in
/// `scoped_body_replace` requires a full `serde_json` parse tree to enforce
/// the field-level substitution allowlist (F9). Streaming JSON without that
/// tree would bypass F9 and could leak secrets into non-allowed fields such
/// as `prompt` or `content`. We prefer correctness over memory savings for
/// the JSON case — JSON always uses the buffered path.
///
/// Form data is also intentionally excluded: it requires a complete bounded
/// body so substitution can be restricted to explicitly allowed field names.
/// Binary and unknown types return `false` and remain buffered (passed through
/// unchanged by `scoped_body_replace`).
pub fn should_stream_replace(content_type: Option<&str>) -> bool {
    let ct = match content_type {
        Some(ct) if !ct.is_empty() => ct,
        _ => return false,
    };
    let mime = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime.starts_with("text/")
}

/// Perform streaming phantom-token replacement on a single incoming frame.
///
/// Prepends `carry` (tail bytes held from the previous frame) to `frame`,
/// runs `replace_in_bytes` over the combined buffer, then:
/// - Returns the "ready" prefix (everything except the last
///   `PHM_TOKEN_MAX_PARTIAL` bytes) for immediate emission.
/// - Updates `carry` with the held tail for the next call.
///
/// After the last frame, call `stream_replace_flush` to drain the carry.
///
/// This performs simple substring replacement with no field-level scoping.
/// It must only be called for content-types where `should_stream_replace`
/// returns `true`.
pub fn stream_replace_frame(
    interceptor: &Interceptor,
    carry: &mut Vec<u8>,
    frame: &[u8],
) -> Vec<u8> {
    let mut combined = Vec::with_capacity(carry.len() + frame.len());
    combined.extend_from_slice(carry);
    combined.extend_from_slice(frame);

    let (replaced, _did_replace) = interceptor.replace_in_bytes(&combined);

    if replaced.len() > PHM_TOKEN_MAX_PARTIAL {
        let emit_end = replaced.len() - PHM_TOKEN_MAX_PARTIAL;
        let ready = replaced[..emit_end].to_vec();
        *carry = replaced[emit_end..].to_vec();
        ready
    } else {
        // Short combined buffer — carry it all; nothing ready yet.
        *carry = replaced;
        Vec::new()
    }
}

/// Flush the carry buffer after the last frame. Runs a final replacement
/// pass and returns the bytes to emit.
pub fn stream_replace_flush(interceptor: &Interceptor, carry: Vec<u8>) -> Vec<u8> {
    if carry.is_empty() {
        return Vec::new();
    }
    let (replaced, _) = interceptor.replace_in_bytes(&carry);
    replaced
}

/// Apply phantom-token substitution to a request body, restricted by
/// content-type. Returns the (possibly rewritten) body and whether any
/// substitution happened.
///
/// - `application/json` (and `*+json`): recursively replaces phm tokens
///   inside string values whose parent key is in the allowlist. Tokens
///   outside allowed fields are left untouched and a warning is logged.
/// - `application/x-www-form-urlencoded`: replaces phm tokens only inside
///   values whose exact field name is in the same auth-field allowlist.
/// - Any other / absent content-type: body is returned unchanged. If a phm
///   token is present a debug log is emitted; no substitution is performed.
pub fn scoped_body_replace(
    interceptor: &Interceptor,
    content_type: Option<&str>,
    body: &[u8],
) -> (Vec<u8>, bool) {
    scoped_body_replace_inner(interceptor, None, content_type, body)
}

/// Route-scoped body substitution used by the network proxy. Only the token
/// owned by `secret_key` can resolve, even in an otherwise allowed field.
pub fn scoped_body_replace_for_secret(
    interceptor: &Interceptor,
    secret_key: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> (Vec<u8>, bool) {
    scoped_body_replace_inner(interceptor, Some(secret_key), content_type, body)
}

fn scoped_body_replace_inner(
    interceptor: &Interceptor,
    secret_key: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> (Vec<u8>, bool) {
    let ct = content_type.unwrap_or("");
    if is_json_content_type(ct) {
        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(mut v) => {
                let replaced = replace_in_json(&mut v, interceptor, secret_key);
                if replaced {
                    match serde_json::to_vec(&v) {
                        Ok(out) => (out, true),
                        Err(_) => (body.to_vec(), false),
                    }
                } else {
                    warn_if_phantom_present(interceptor, body, "JSON body outside allowed fields");
                    (body.to_vec(), false)
                }
            }
            Err(_) => {
                warn_if_phantom_present(interceptor, body, "malformed JSON body");
                (body.to_vec(), false)
            }
        }
    } else if is_form_content_type(ct) {
        replace_in_form(interceptor, secret_key, body)
    } else {
        if !body.is_empty() {
            if let Ok(s) = std::str::from_utf8(body) {
                if interceptor.contains_phantom_token(s) {
                    debug!(
                        "phantom token in request body with content-type {:?} — not substituted (F9 scope)",
                        ct
                    );
                }
            }
        }
        (body.to_vec(), false)
    }
}

/// Replace credentials in a bounded URL-encoded form without parsing or
/// reserializing it. Phantom tokens use only unreserved URL characters, so an
/// exact byte-preserving split is sufficient: encoded or malformed keys fail
/// closed, and values in non-auth fields are never inspected for replacement.
fn replace_in_form(
    interceptor: &Interceptor,
    secret_key: Option<&str>,
    body: &[u8],
) -> (Vec<u8>, bool) {
    let Ok(form) = std::str::from_utf8(body) else {
        return (body.to_vec(), false);
    };

    let mut output = String::with_capacity(form.len());
    let mut replaced = false;
    for (index, field) in form.split('&').enumerate() {
        if index > 0 {
            output.push('&');
        }

        let Some((name, value)) = field.split_once('=') else {
            output.push_str(field);
            continue;
        };
        output.push_str(name);
        output.push('=');

        if is_allowed_json_field(name) {
            let (new_value, did_replace) = match secret_key {
                Some(secret_key) => interceptor.replace_in_str_for_secret(value, secret_key),
                None => interceptor.replace_in_str(value),
            };
            output.push_str(&new_value);
            replaced |= did_replace;
        } else {
            output.push_str(value);
        }
    }

    if !replaced {
        warn_if_phantom_present(
            interceptor,
            body,
            "form body outside allowed fields or route scope",
        );
    }
    (output.into_bytes(), replaced)
}

fn warn_if_phantom_present(interceptor: &Interceptor, body: &[u8], ctx: &str) {
    if let Ok(s) = std::str::from_utf8(body) {
        if interceptor.contains_phantom_token(s) {
            warn!("phantom token in {ctx} — not substituted (F9 scope)");
        }
    }
}

fn replace_in_json(
    value: &mut serde_json::Value,
    interceptor: &Interceptor,
    secret_key: Option<&str>,
) -> bool {
    let mut replaced = false;
    match value {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let allowed = is_allowed_json_field(&key);
                if let Some(child) = map.get_mut(&key) {
                    if allowed {
                        if let serde_json::Value::String(s) = child {
                            let (new_s, did) = match secret_key {
                                Some(secret_key) => {
                                    interceptor.replace_in_str_for_secret(s, secret_key)
                                }
                                None => interceptor.replace_in_str(s),
                            };
                            if did {
                                debug!("Replaced phantom token in JSON field: {}", key);
                                *s = new_s;
                                replaced = true;
                            }
                        }
                    }
                    // Recurse regardless so nested allowed fields are still handled
                    if replace_in_json(child, interceptor, secret_key) {
                        replaced = true;
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                if replace_in_json(item, interceptor, secret_key) {
                    replaced = true;
                }
            }
        }
        _ => {}
    }
    replaced
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const PHM: &str = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
    const REAL: &str = "sk-real-openai-key-12345";

    fn interceptor() -> Interceptor {
        let mut m = HashMap::new();
        m.insert(PHM.to_string(), REAL.to_string());
        Interceptor::new(m)
    }

    #[test]
    fn allowed_header_default_list() {
        assert!(is_allowed_header("Authorization", ""));
        assert!(is_allowed_header("authorization", ""));
        assert!(is_allowed_header("X-API-Key", ""));
        assert!(is_allowed_header("Cookie", ""));
    }

    #[test]
    fn allowed_header_per_service() {
        assert!(is_allowed_header("X-Custom-Auth", "x-custom-auth"));
        assert!(is_allowed_header("x-custom-auth", "X-Custom-Auth"));
    }

    #[test]
    fn disallowed_header_rejected() {
        assert!(!is_allowed_header("User-Agent", ""));
        assert!(!is_allowed_header("X-Request-Id", "authorization"));
        assert!(!is_allowed_header("Content-Type", ""));
    }

    #[test]
    fn json_content_type_detection() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("APPLICATION/JSON"));
        assert!(is_json_content_type("application/vnd.api+json"));
        assert!(!is_json_content_type("text/plain"));
        assert!(!is_json_content_type("application/xml"));
        assert!(!is_json_content_type(""));
    }

    #[test]
    fn json_body_allowed_field_replaced() {
        let body = format!(r#"{{"model":"gpt-4","api_key":"{PHM}"}}"#);
        let (out, did) =
            scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
        assert!(did);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains(REAL));
        assert!(!out_str.contains("phm_"));
    }

    #[test]
    fn json_body_disallowed_field_not_replaced() {
        // `prompt` is not in the allowlist — a phm_ token that happens to land
        // in chat message content must NOT be substituted.
        let body = format!(r#"{{"prompt":"I saw {PHM} in logs","model":"gpt-4"}}"#);
        let (out, did) =
            scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
        assert!(!did);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(
            out_str.contains(PHM),
            "phm token should survive un-substituted"
        );
        assert!(!out_str.contains(REAL));
    }

    #[test]
    fn json_body_nested_allowed_field_replaced() {
        let body = format!(r#"{{"config":{{"auth_token":"{PHM}"}}}}"#);
        let (out, did) =
            scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
        assert!(did);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains(REAL));
    }

    #[test]
    fn json_body_multiple_fields_mixed() {
        let body = format!(
            r#"{{"api_key":"{PHM}","prompt":"contains {PHM} too","messages":[{{"role":"user","content":"tell me about {PHM}"}}]}}"#
        );
        let (out, did) =
            scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
        assert!(did);
        let out_str = std::str::from_utf8(&out).unwrap();
        // api_key got replaced
        assert!(out_str.contains(REAL));
        // But the phm token in `prompt` and `content` remains
        assert!(out_str.contains(PHM));
    }

    #[test]
    fn form_body_allowed_field_replaced() {
        let body = format!("grant_type=client_credentials&client_secret={PHM}");
        let (out, did) = scoped_body_replace(
            &interceptor(),
            Some("application/x-www-form-urlencoded"),
            body.as_bytes(),
        );
        assert!(did);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(!out_str.contains(PHM));
        assert!(out_str.contains(REAL));
    }

    #[test]
    fn form_body_disallowed_field_not_replaced() {
        let body = format!("prompt={PHM}&grant_type=client_credentials");
        let (out, did) = scoped_body_replace(
            &interceptor(),
            Some("application/x-www-form-urlencoded"),
            body.as_bytes(),
        );
        assert!(!did);
        assert_eq!(out, body.as_bytes());
    }

    #[test]
    fn malformed_json_not_replaced() {
        let body = format!(r#"{{"api_key": "{PHM}""#); // missing closing
        let (out, did) =
            scoped_body_replace(&interceptor(), Some("application/json"), body.as_bytes());
        assert!(!did);
        assert_eq!(out, body.as_bytes());
    }

    #[test]
    fn empty_body_passes_through() {
        let (out, did) = scoped_body_replace(&interceptor(), Some("application/json"), b"");
        assert!(!did);
        assert_eq!(out, b"");
    }

    #[test]
    fn content_type_with_charset_still_parses() {
        let body = format!(r#"{{"api_key":"{PHM}"}}"#);
        let (out, did) = scoped_body_replace(
            &interceptor(),
            Some("application/json; charset=utf-8"),
            body.as_bytes(),
        );
        assert!(did);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains(REAL));
    }

    // --- should_stream_replace ---

    #[test]
    fn stream_replace_text_plain() {
        assert!(should_stream_replace(Some("text/plain")));
    }

    #[test]
    fn stream_replace_text_event_stream() {
        assert!(should_stream_replace(Some("text/event-stream")));
    }

    #[test]
    fn stream_replace_text_with_charset() {
        assert!(should_stream_replace(Some("text/plain; charset=utf-8")));
    }

    #[test]
    fn stream_replace_form_encoded_excluded_for_field_scoping() {
        assert!(!should_stream_replace(Some(
            "application/x-www-form-urlencoded"
        )));
    }

    #[test]
    fn stream_replace_json_excluded() {
        // JSON must use the buffered path for F9 field-level scoping.
        assert!(!should_stream_replace(Some("application/json")));
        assert!(!should_stream_replace(Some("application/vnd.api+json")));
    }

    #[test]
    fn stream_replace_binary_excluded() {
        assert!(!should_stream_replace(Some("application/octet-stream")));
        assert!(!should_stream_replace(Some("image/png")));
        assert!(!should_stream_replace(Some("multipart/form-data")));
    }

    #[test]
    fn stream_replace_none_excluded() {
        assert!(!should_stream_replace(None));
        assert!(!should_stream_replace(Some("")));
    }

    // --- stream_replace_frame / stream_replace_flush ---

    #[test]
    fn stream_frame_whole_token_in_one_frame() {
        let iceptor = interceptor();
        let mut carry = Vec::new();
        let input = format!("prefix-{PHM}-suffix");
        let ready = stream_replace_frame(&iceptor, &mut carry, input.as_bytes());
        let flushed = stream_replace_flush(&iceptor, carry);
        let result = [ready, flushed].concat();
        let s = std::str::from_utf8(&result).unwrap();
        assert!(s.contains(REAL), "real secret not found: {s}");
        assert!(!s.contains("phm_"), "phantom token still present: {s}");
    }

    #[test]
    fn stream_frame_token_split_across_frames() {
        let iceptor = interceptor();
        let mut carry = Vec::new();

        // Split the 68-char token at position 20
        let split = 20;
        let part1 = format!("key={}", &PHM[..split]);
        let part2 = format!("{}&ok=1", &PHM[split..]);

        let ready1 = stream_replace_frame(&iceptor, &mut carry, part1.as_bytes());
        let ready2 = stream_replace_frame(&iceptor, &mut carry, part2.as_bytes());
        let flushed = stream_replace_flush(&iceptor, carry);

        let result = [ready1, ready2, flushed].concat();
        let s = std::str::from_utf8(&result).unwrap();
        assert!(s.contains(REAL), "real secret not found after split: {s}");
        assert!(!s.contains("phm_"), "phantom token still present: {s}");
    }

    #[test]
    fn stream_frame_token_split_at_every_position() {
        let iceptor = interceptor();
        for split in 1..PHM.len() {
            let mut carry = Vec::new();
            let part1 = &PHM.as_bytes()[..split];
            let part2 = &PHM.as_bytes()[split..];

            let r1 = stream_replace_frame(&iceptor, &mut carry, part1);
            let r2 = stream_replace_frame(&iceptor, &mut carry, part2);
            let flushed = stream_replace_flush(&iceptor, carry);

            let result = [r1, r2, flushed].concat();
            let s = std::str::from_utf8(&result).unwrap();
            assert!(
                s.contains(REAL),
                "real secret missing at split={split}: {s}"
            );
            assert!(
                !s.contains("phm_"),
                "phantom token present at split={split}: {s}"
            );
        }
    }

    #[test]
    fn stream_frame_no_token_passes_through() {
        let iceptor = interceptor();
        let mut carry = Vec::new();
        let input = b"no secrets here, just plain text";
        let ready = stream_replace_frame(&iceptor, &mut carry, input);
        let flushed = stream_replace_flush(&iceptor, carry);
        let result = [ready, flushed].concat();
        assert_eq!(result, input);
    }

    #[test]
    fn stream_flush_empty_carry() {
        let iceptor = interceptor();
        let result = stream_replace_flush(&iceptor, Vec::new());
        assert!(result.is_empty());
    }
}
