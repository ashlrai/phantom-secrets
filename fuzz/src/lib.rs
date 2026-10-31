//! Property oracles shared by libFuzzer and deterministic regression tests.

use phantom_core::token::PhantomToken;
use phantom_proxy::{body_scope, Interceptor};
use std::collections::HashMap;

// Entirely synthetic fixtures, unrelated to any project mapping or credential.
pub const PLACEHOLDER: &str = concat!(
    "phm_",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
);
const OTHER_PLACEHOLDER: &str = "phm_fuzz_other";
const ROUTE: &str = "FUZZ_ROUTE";
const VALUE: &str = "synthetic-fuzz-value-only";

pub fn placeholder_parsing(data: &[u8]) {
    // Lossy conversion also drives invalid UTF-8 mutations through the str API.
    let text = String::from_utf8_lossy(data);
    check_parser(&text);
    check_parser(&format!("phm_{text}"));
    check_parser(&format!(" {text}"));
}

fn check_parser(text: &str) {
    // The public parser intentionally recognizes a prefix, not a hex grammar.
    let expected = text.as_bytes().starts_with(b"phm_");
    let parsed = PhantomToken::parse(text);
    assert!(parsed.is_some() == expected, "parser acceptance changed");
    assert!(PhantomToken::is_phantom_token(text) == expected);
    if let Some(parsed) = parsed {
        assert!(parsed.as_str() == text, "parser altered input");
        assert!(parsed.to_string() == text);
        assert!(PhantomToken::parse(parsed.as_str()).as_ref() == Some(&parsed));
    }
}

// These deprecated APIs are intentionally retained upstream as fail-closed
// compatibility boundaries. Fuzzing them must never re-enable substitution.
#[allow(deprecated)]
pub fn body_injection(data: &[u8]) {
    let mappings = HashMap::from([
        (PLACEHOLDER.to_owned(), (ROUTE.to_owned(), VALUE.to_owned())),
        (
            OTHER_PLACEHOLDER.to_owned(),
            ("FUZZ_OTHER".to_owned(), "synthetic-other-value".to_owned()),
        ),
    ]);
    let named = HashMap::from([(ROUTE.to_owned(), VALUE.to_owned())]);
    let interceptor = match data.first().copied().unwrap_or(0) % 3 {
        0 => Interceptor::new_scoped(mappings, named),
        mode => {
            let values = mappings.into_iter().map(|(k, (_, v))| (k, v)).collect();
            if mode == 1 {
                Interceptor::new_with_named(values, named)
            } else {
                Interceptor::new(values)
            }
        }
    };
    let content_type = String::from_utf8_lossy(data);
    let types = [
        None,
        Some("application/json"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=fuzz"),
        Some("text/plain; charset=utf-8"),
        Some("application/octet-stream"),
        Some(content_type.as_ref()),
    ];
    let mime = types[data.get(1).copied().unwrap_or(0) as usize % types.len()];
    let route = match data.get(2).copied().unwrap_or(0) % 3 {
        0 => ROUTE,
        1 => "FUZZ_MISSING",
        _ => content_type.as_ref(),
    };

    // Controls are separate from payload so corpus JSON/form inputs stay valid.
    // Valid structured wrappers always contain a known mapping, even when the
    // mutated payload is binary, catching format-specific substitution too.
    let payload = data.get(6..).unwrap_or_default();
    let json = serde_json::to_vec(&serde_json::json!({
        "api_key": PLACEHOLDER, "nested": {"client_secret": OTHER_PLACEHOLDER},
        "payload": String::from_utf8_lossy(payload),
    }))
    .expect("synthetic JSON serializes");
    let form = format!("api_key={PLACEHOLDER}&client_secret={OTHER_PLACEHOLDER}");
    let multipart = format!(
        "--fuzz\r\nContent-Disposition: form-data; name=\"api_key\"\r\n\r\n{PLACEHOLDER}\r\n--fuzz--\r\n"
    );
    let mut envelope = PLACEHOLDER.as_bytes().to_vec();
    envelope.extend_from_slice(payload);
    for body in [
        payload,
        json.as_slice(),
        form.as_bytes(),
        multipart.as_bytes(),
        envelope.as_slice(),
    ] {
        let (out, changed) = body_scope::scoped_body_replace(&interceptor, mime, body);
        assert!(!changed && out == body, "body substitution enabled");
        let (out, changed) =
            body_scope::scoped_body_replace_for_secret(&interceptor, route, mime, body);
        assert!(!changed && out == body, "route body substitution enabled");
        let (out, changed) = interceptor.replace_in_bytes(body);
        assert!(!changed && out == body);
        let (out, changed) = interceptor.replace_in_bytes_for_secret(body, route);
        assert!(!changed && out == body);

        // Vary both the initial carry and frame boundaries, including empties.
        let split_selector = u16::from_le_bytes([
            data.get(4).copied().unwrap_or(0),
            data.get(5).copied().unwrap_or(0),
        ]);
        let split = split_selector as usize % (body.len() + 1);
        let width = data.get(3).copied().unwrap_or(0) as usize + 1;
        let mut carry = body[..split].to_vec();
        let mut streamed = body_scope::stream_replace_frame(&interceptor, &mut carry, &[]);
        for frame in body[split..].chunks(width) {
            streamed.extend(body_scope::stream_replace_frame(
                &interceptor,
                &mut carry,
                frame,
            ));
        }
        streamed.extend(body_scope::stream_replace_flush(&interceptor, carry));
        assert!(streamed == body, "stream altered request bytes");

        let text = String::from_utf8_lossy(body);
        let (out, changed) = interceptor.replace_in_str(&text);
        assert!(!changed && out == text);
        let (out, changed) = interceptor.replace_in_str_for_secret(&text, route);
        assert!(!changed && out == text);
        assert!(!interceptor.contains_phantom_token(&text));
        assert!(!interceptor.contains_phantom_token_for_secret(&text, route));
        assert!(interceptor.resolve(&text).is_none());
        assert!(interceptor
            .format_header_value(&text, PLACEHOLDER)
            .is_none());
        assert!(!body_scope::is_allowed_header(&text, "Authorization"));
    }
    assert!(!body_scope::should_stream_replace(mime));
    assert!(interceptor.resolve(PLACEHOLDER).is_none());
    assert!(interceptor
        .format_header_for_secret_key("Bearer {secret}", "FUZZ_MISSING")
        .is_none());
    let header = interceptor.format_header_for_secret_key("Bearer {secret}", ROUTE);
    if data.first().copied().unwrap_or(0) % 3 == 2 {
        assert!(header.is_none());
    } else {
        assert!(header.as_deref() == Some("Bearer synthetic-fuzz-value-only"));
    }
}
