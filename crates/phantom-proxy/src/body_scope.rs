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

/// Apply phantom-token substitution to a request body, restricted by
/// content-type. Returns the (possibly rewritten) body and whether any
/// substitution happened.
///
/// - `application/json` (and `*+json`): recursively replaces phm tokens
///   inside string values whose parent key is in the allowlist. Tokens
///   outside allowed fields are left untouched and a warning is logged.
/// - Any other / absent content-type: body is returned unchanged. If a phm
///   token is present a debug log is emitted; no substitution is performed.
pub fn scoped_body_replace(
    interceptor: &Interceptor,
    content_type: Option<&str>,
    body: &[u8],
) -> (Vec<u8>, bool) {
    let ct = content_type.unwrap_or("");
    if is_json_content_type(ct) {
        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(mut v) => {
                let replaced = replace_in_json(&mut v, interceptor);
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

fn warn_if_phantom_present(interceptor: &Interceptor, body: &[u8], ctx: &str) {
    if let Ok(s) = std::str::from_utf8(body) {
        if interceptor.contains_phantom_token(s) {
            warn!("phantom token in {ctx} — not substituted (F9 scope)");
        }
    }
}

fn replace_in_json(value: &mut serde_json::Value, interceptor: &Interceptor) -> bool {
    let mut replaced = false;
    match value {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let allowed = is_allowed_json_field(&key);
                if let Some(child) = map.get_mut(&key) {
                    if allowed {
                        if let serde_json::Value::String(s) = child {
                            let (new_s, did) = interceptor.replace_in_str(s);
                            if did {
                                debug!("Replaced phantom token in JSON field: {}", key);
                                *s = new_s;
                                replaced = true;
                            }
                        }
                    }
                    // Recurse regardless so nested allowed fields are still handled
                    if replace_in_json(child, interceptor) {
                        replaced = true;
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                if replace_in_json(item, interceptor) {
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
    fn non_json_body_not_replaced() {
        let body = format!("grant_type=client_credentials&client_secret={PHM}");
        let (out, did) = scoped_body_replace(
            &interceptor(),
            Some("application/x-www-form-urlencoded"),
            body.as_bytes(),
        );
        assert!(!did);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains(PHM));
        assert!(!out_str.contains(REAL));
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
}
