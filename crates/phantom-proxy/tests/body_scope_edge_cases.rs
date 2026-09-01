//! Regression matrix for the 0.7.4 client-substitution denial boundary.
//!
//! Every client-controlled header/body compatibility helper must leave bytes
//! unchanged. The network proxy injects credentials only through a matched
//! route's fixed configured authentication header.

#![allow(deprecated)]

use phantom_proxy::body_scope::{
    is_allowed_header, scoped_body_replace, scoped_body_replace_for_secret,
};
use phantom_proxy::Interceptor;
use std::collections::HashMap;

const PHM: &str = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
const REAL: &str = "sk-real-openai-key-abcdef";

fn interceptor() -> Interceptor {
    Interceptor::new(HashMap::from([(PHM.to_string(), REAL.to_string())]))
}

fn assert_body_is_inert(content_type: Option<&str>, body: &[u8]) {
    #[allow(deprecated)]
    let (unscoped, unscoped_replaced) = scoped_body_replace(&interceptor(), content_type, body);
    assert!(!unscoped_replaced);
    assert_eq!(unscoped, body);

    #[allow(deprecated)]
    let (route_scoped, route_scoped_replaced) =
        scoped_body_replace_for_secret(&interceptor(), "API_KEY", content_type, body);
    assert!(!route_scoped_replaced);
    assert_eq!(route_scoped, body);
    assert!(!String::from_utf8_lossy(&route_scoped).contains(REAL));
}

#[test]
fn structured_nested_and_injected_fields_never_resolve() {
    for body in [
        format!(r#"{{"api_key":"{PHM}"}}"#),
        format!(r#"{{"tool":{{"arguments":{{"api_key":"{PHM}"}}}}}}"#),
        format!(r#"[{{"token":"{PHM}"}},{{"client_secret":"{PHM}"}}]"#),
        format!(r#"{{"prompt":"{PHM}","authorization":"{PHM}"}}"#),
    ] {
        assert_body_is_inert(Some("application/json"), body.as_bytes());
        assert_body_is_inert(Some("application/vnd.api+json"), body.as_bytes());
    }
}

#[test]
fn form_text_malformed_binary_and_unknown_bodies_never_resolve() {
    let cases: &[(Option<&str>, Vec<u8>)] = &[
        (
            Some("application/x-www-form-urlencoded"),
            format!("client_secret={PHM}&grant_type=client_credentials").into_bytes(),
        ),
        (Some("text/plain"), format!("credential={PHM}").into_bytes()),
        (
            Some("application/json"),
            format!(r#"{{"api_key":"{PHM}""#).into_bytes(),
        ),
        (
            Some("multipart/form-data; boundary=x"),
            format!("--x\r\n\r\n{PHM}\r\n--x--").into_bytes(),
        ),
        (
            Some("application/octet-stream"),
            [vec![0xff, 0xfe], PHM.as_bytes().to_vec()].concat(),
        ),
        (Some("application/x-custom"), PHM.as_bytes().to_vec()),
        (None, PHM.as_bytes().to_vec()),
        (Some("application/json"), Vec::new()),
    ];

    for (content_type, body) in cases {
        assert_body_is_inert(*content_type, body);
    }
}

#[test]
#[allow(deprecated)]
fn no_client_header_is_eligible_for_substitution() {
    for (header, configured) in [
        ("Authorization", "Authorization"),
        ("X-API-Key", "X-API-Key"),
        ("Cookie", "Authorization"),
        ("Proxy-Authorization", "Authorization"),
        ("X-Custom-Auth", "X-Custom-Auth"),
        ("User-Agent", "Authorization"),
    ] {
        assert!(!is_allowed_header(header, configured));
    }
}
