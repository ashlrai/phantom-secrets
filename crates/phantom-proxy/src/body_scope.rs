//! Compatibility surface for the former client-token substitution helpers.
//!
//! Phantom 0.7.4 deliberately does not resolve client-controlled `phm_`
//! tokens in request headers or bodies. A matched proxy route injects only its
//! configured vault secret into its exact configured authentication header.
//! These functions remain available so patch upgrades do not break source
//! consumers, but every one is fail-closed and performs no substitution.

use crate::interceptor::Interceptor;

/// Phantom token format length retained for source compatibility with 0.7.3.
pub const PHM_TOKEN_LEN: usize = 68;
/// Retained for source compatibility; request streaming substitution is disabled.
pub const PHM_TOKEN_MAX_PARTIAL: usize = PHM_TOKEN_LEN - 1;

/// Compatibility predicate for the former client-header substitution API.
///
/// Client-controlled headers are never eligible for token resolution. The
/// proxy injects a route-owned credential independently of this function.
#[deprecated(note = "client-controlled header substitution is disabled")]
pub fn is_allowed_header(_name: &str, _service_header: &str) -> bool {
    false
}

/// Unstructured request streaming substitution is disabled for every content
/// type.
#[deprecated(note = "client-controlled request substitution is disabled")]
pub fn should_stream_replace(_content_type: Option<&str>) -> bool {
    false
}

/// Compatibility pass-through for callers compiled against the former
/// streaming request API.
#[deprecated(note = "client-controlled request substitution is disabled; bytes pass through")]
pub fn stream_replace_frame(
    _interceptor: &Interceptor,
    carry: &mut Vec<u8>,
    frame: &[u8],
) -> Vec<u8> {
    let mut output = std::mem::take(carry);
    output.extend_from_slice(frame);
    output
}

/// Compatibility pass-through for the former streaming request API.
#[deprecated(note = "client-controlled request substitution is disabled; bytes pass through")]
pub fn stream_replace_flush(_interceptor: &Interceptor, carry: Vec<u8>) -> Vec<u8> {
    carry
}

/// Compatibility pass-through for the former request-body substitution API.
///
/// The content type is intentionally ignored. JSON, form, text, malformed,
/// binary, multipart, and absent-content-type bodies all remain byte-identical.
#[deprecated(note = "client-controlled request substitution is disabled; bytes pass through")]
pub fn scoped_body_replace(
    _interceptor: &Interceptor,
    _content_type: Option<&str>,
    body: &[u8],
) -> (Vec<u8>, bool) {
    (body.to_vec(), false)
}

/// Route-parameter compatibility pass-through for the former body API.
///
/// `secret_key` does not authorize a client body to resolve a token. Route
/// credentials are injected only by the proxy server into the configured auth
/// header.
#[deprecated(note = "client-controlled request substitution is disabled; bytes pass through")]
pub fn scoped_body_replace_for_secret(
    _interceptor: &Interceptor,
    _secret_key: &str,
    _content_type: Option<&str>,
    body: &[u8],
) -> (Vec<u8>, bool) {
    (body.to_vec(), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const PHM: &str = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
    const REAL: &str = "sk-real-openai-key-12345";

    fn interceptor() -> Interceptor {
        Interceptor::new(HashMap::from([(PHM.to_string(), REAL.to_string())]))
    }

    #[test]
    #[allow(deprecated)]
    fn every_client_substitution_compatibility_api_is_fail_closed() {
        for (content_type, body) in [
            (
                Some("application/json"),
                format!(r#"{{"api_key":"{PHM}"}}"#),
            ),
            (
                Some("application/x-www-form-urlencoded"),
                format!("client_secret={PHM}"),
            ),
            (Some("text/plain"), format!("credential={PHM}")),
            (Some("application/octet-stream"), PHM.to_string()),
            (None, PHM.to_string()),
        ] {
            assert!(!should_stream_replace(content_type));
            let (out, replaced) =
                scoped_body_replace(&interceptor(), content_type, body.as_bytes());
            assert!(!replaced);
            assert_eq!(out, body.as_bytes());
            let (out, replaced) = scoped_body_replace_for_secret(
                &interceptor(),
                "API_KEY",
                content_type,
                body.as_bytes(),
            );
            assert!(!replaced);
            assert_eq!(out, body.as_bytes());
            assert!(!String::from_utf8_lossy(&out).contains(REAL));
        }

        for header in ["Authorization", "X-API-Key", "Cookie", "X-Custom-Auth"] {
            assert!(!is_allowed_header(header, "X-Custom-Auth"));
        }
    }

    #[test]
    #[allow(deprecated)]
    fn streaming_compatibility_api_is_byte_preserving() {
        let iceptor = interceptor();
        let mut carry = b"prefix-".to_vec();
        let frame = format!("{PHM}-suffix");
        let output = stream_replace_frame(&iceptor, &mut carry, frame.as_bytes());
        assert_eq!(output, format!("prefix-{frame}").as_bytes());
        assert!(stream_replace_flush(&iceptor, carry).is_empty());
        assert!(!String::from_utf8_lossy(&output).contains(REAL));
    }
}
