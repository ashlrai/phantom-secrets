//! Exhaustive transport-boundary tables for managed response representations.
//! All credentials are artificial fixtures; the integration test is loopback-only.

use base64::{engine::general_purpose, Engine as _};
use phantom_core::audit::{LeakLocation, LeakSeverity};
use phantom_proxy::{ResponseScrubber, ScrubEvent, StreamingScrubState};
use std::collections::HashMap;

const MARKER: &str = "[REDACTED:vault-secret]";
// The aligned UTF-8 bytes produce both '+' and '/' in standard Base64.
const FIXTURE: &str = "FAKE__\u{ffff} /+%?=~";

fn scrubber(values: &[(&str, &str)]) -> ResponseScrubber {
    ResponseScrubber::from_named_map(
        &values
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
    )
}

fn percent(value: &str, variant: usize) -> String {
    let mut out = String::new();
    for (index, byte) in value.bytes().enumerate() {
        let unreserved = byte.is_ascii_alphanumeric() || b"-._~".contains(&byte);
        if variant == 4 && byte == b' ' {
            out.push('+');
        } else if unreserved && (variant >= 3 || (variant == 2 && index % 3 == 0)) {
            out.push(char::from(byte));
        } else if variant == 5 {
            out.push_str(&format!("%{:x}{:X}", byte >> 4, byte & 0xf));
        } else if variant == 1 || (variant == 2 && index % 2 == 0) {
            out.push_str(&format!("%{byte:02x}"));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn representations(value: &str) -> Vec<String> {
    let mut forms = vec![value.to_string()];
    for engine in [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD,
    ] {
        forms.push(engine.encode(value));
    }
    forms.extend((0..6).map(|variant| percent(value, variant)));
    forms.sort();
    forms.dedup();
    forms
}

fn stream<'a>(
    scrubber: &ResponseScrubber,
    content_type: Option<&str>,
    chunks: impl IntoIterator<Item = &'a [u8]>,
) -> (Vec<u8>, Vec<ScrubEvent>) {
    let mut state = StreamingScrubState::new();
    let mut output = Vec::new();
    let mut events = Vec::new();
    for chunk in chunks {
        let (ready, event) = scrubber.scrub_stream_chunk(content_type, &mut state, chunk);
        output.extend(ready);
        events.push(event);
        assert!(state.buffered_len() <= scrubber.stream_buffer_bound());
    }
    let (tail, event) = scrubber.finish_stream(content_type, state);
    output.extend(tail);
    events.push(event);
    (output, events)
}

fn assert_event_count(events: &[ScrubEvent], expected: usize) {
    let mut count = 0;
    for event in events {
        assert_eq!(event.scrubbed, !event.leak_events.is_empty());
        assert!(event.adaptive_hits.is_empty());
        for leak in &event.leak_events {
            assert_eq!(leak.location, LeakLocation::Body);
            assert_eq!(leak.severity, LeakSeverity::High);
            assert!(leak.secret_name.is_some());
            assert_eq!(leak.pattern, "vault-secret");
            count += leak.match_count;
        }
    }
    assert_eq!(count, expected);
}

#[test]
fn every_representation_is_redacted_at_every_two_part_boundary() {
    // Lengths modulo three exercise zero, one, and two Base64 padding bytes.
    for value in [FIXTURE, "~", "~!", "~!@", "FAKEopaque9token7only5TEST"] {
        let scrubber = scrubber(&[("FIXTURE", value)]);
        for representation in representations(value) {
            for (content_type, prefix, suffix) in [
                (Some("text/plain"), "before|", "|after"),
                (Some("application/json"), "{\"echo\":\"", "\"}"),
                (Some("text/event-stream"), "data: ", "\r\n\r\n"),
                (None, "\0before|", "|after\0"),
            ] {
                let body = format!("{prefix}{representation}{suffix}");
                let expected = format!("{prefix}{MARKER}{suffix}");
                for split in 0..=body.len() {
                    let (output, events) = stream(
                        &scrubber,
                        content_type,
                        [&body.as_bytes()[..split], &body.as_bytes()[split..]],
                    );
                    assert_eq!(output, expected.as_bytes(), "split {split}");
                    assert_event_count(&events, 1);
                }
            }
        }
    }
}

#[test]
fn arbitrary_repeated_chunk_sizes_preserve_framing_and_redact_once() {
    let scrubber = scrubber(&[("FIXTURE", FIXTURE)]);
    for representation in representations(FIXTURE) {
        let body = format!("data: {representation}\n\nevent: done\n\n");
        for size in 1..=body.len() {
            let (output, events) = stream(
                &scrubber,
                Some("text/event-stream"),
                body.as_bytes().chunks(size),
            );
            assert_eq!(
                output,
                format!("data: {MARKER}\n\nevent: done\n\n").as_bytes()
            );
            assert_event_count(&events, 1);
        }
    }
}

#[test]
fn complete_candidates_are_redacted_when_eof_is_the_only_delimiter() {
    let scrubber = scrubber(&[("FIXTURE", FIXTURE)]);
    for representation in representations(FIXTURE) {
        let (output, events) = stream(&scrubber, None, representation.as_bytes().chunks(1));
        assert_eq!(output, MARKER.as_bytes());
        assert_event_count(&events, 1);
    }
}

#[test]
fn incomplete_and_invalid_encoded_candidates_are_byte_preserving() {
    let scrubber = scrubber(&[("FIXTURE", FIXTURE)]);
    let encoded = general_purpose::STANDARD.encode(FIXTURE);
    let prefixes = [
        "%".to_string(),
        "%4".to_string(),
        "%46%41%4".to_string(),
        "%46%41%GG".to_string(),
        "%46%41%K0".to_string(),
        "%46%41%0K".to_string(),
        "%46%41%".to_string(),
        encoded[..encoded.len() / 2].to_string(),
        "FAKE__different".to_string(),
    ];
    for prefix in prefixes {
        for size in 1..=prefix.len() {
            let (output, events) = stream(&scrubber, None, prefix.as_bytes().chunks(size));
            assert_eq!(output, prefix.as_bytes());
            assert_event_count(&events, 0);
        }
    }
}

#[test]
fn adjacent_and_repeated_representations_are_all_redacted() {
    let scrubber = scrubber(&[("FIXTURE", FIXTURE)]);
    let forms = representations(FIXTURE);
    let body = forms.join("");
    for size in [1, 2, 3, 7, 31, 4096] {
        let (output, events) = stream(&scrubber, None, body.as_bytes().chunks(size));
        assert_eq!(output, MARKER.repeat(forms.len()).as_bytes());
        assert_event_count(&events, forms.len());
    }
}

#[test]
fn raw_and_encoded_prefix_collisions_choose_the_longest_complete_match() {
    type CollisionCase<'a> = (&'a [(&'a str, &'a str)], &'a str);
    let cases: &[CollisionCase<'_>] = &[
        (&[("RAW", "fg"), ("ENCODED", "~")], "fg=="),
        (&[("RAW", "fg==suffix"), ("ENCODED", "~")], "fg==suffix"),
        (&[("RAW", "%"), ("ENCODED", "%25tail")], "%25tail"),
        (&[("SHORT", "~!"), ("LONG", "~!@")], "~!@"),
        (&[("SHORT", "~!"), ("LONG", "~!@")], "%7e%21%40"),
        (&[("LITERAL_PLUS", "+"), ("SPACE", " ")], "+"),
    ];
    for (values, body) in cases {
        let scrubber = scrubber(values);
        for split in 0..=body.len() {
            let (output, events) = stream(
                &scrubber,
                None,
                [&body.as_bytes()[..split], &body.as_bytes()[split..]],
            );
            assert_eq!(output, MARKER.as_bytes(), "split {split}");
            assert_event_count(&events, 1);
        }
    }
}

#[test]
fn a_shorter_match_is_committed_when_a_longer_candidate_fails_or_ends() {
    let scrubber = scrubber(&[("SHORT", "fg"), ("LONG", "~")]);
    for (body, expected) in [
        ("fg", MARKER.to_string()),
        ("fg!", format!("{MARKER}!")),
        ("fg=x", format!("{MARKER}=x")),
    ] {
        let (output, events) = stream(&scrubber, None, body.as_bytes().chunks(1));
        assert_eq!(output, expected.as_bytes());
        assert_event_count(&events, 1);
    }
}

#[test]
fn empty_maps_and_empty_values_leave_encoded_text_untouched() {
    for scrubber in [
        ResponseScrubber::from_named_map(&HashMap::new()),
        scrubber(&[("EMPTY", "")]),
    ] {
        let body = representations(FIXTURE).join("|");
        let (output, events) = stream(&scrubber, None, body.as_bytes().chunks(1));
        assert_eq!(output, body.as_bytes());
        assert_event_count(&events, 0);
    }
}

#[test]
fn binary_bytes_utf8_and_empty_chunks_survive_around_encoded_matches() {
    let scrubber = scrubber(&[("FIXTURE", FIXTURE)]);
    let mut body = vec![0xff, 0, 0xc3, 0xa9, b'|'];
    body.extend(percent(FIXTURE, 2).as_bytes());
    body.extend([b'|', 0xf0, 0x9f, 0x92, 0xa1, 0xfe]);
    let mut expected = vec![0xff, 0, 0xc3, 0xa9, b'|'];
    expected.extend(MARKER.as_bytes());
    expected.extend([b'|', 0xf0, 0x9f, 0x92, 0xa1, 0xfe]);
    let chunks = body.chunks(1).flat_map(|byte| [byte, &[][..]]);
    let (output, events) = stream(&scrubber, Some("application/octet-stream"), chunks);
    assert_eq!(output, expected);
    assert_event_count(&events, 1);
}

#[test]
fn long_encoded_candidates_remain_bounded_and_release_clean_output() {
    let value = format!("FAKE {} / ending", "x".repeat(512));
    let scrubber = scrubber(&[("LONG", &value)]);
    let mut state = StreamingScrubState::new();
    let clean = b"ordinary response text\n".repeat(1000);
    let (output, event) = scrubber.scrub_stream_chunk(None, &mut state, &clean);
    assert_eq!(output, clean);
    assert!(!event.scrubbed);
    assert_eq!(state.buffered_len(), 0);
    assert!(scrubber.finish_stream(None, state).0.is_empty());

    for representation in [percent(&value, 0), general_purpose::STANDARD.encode(&value)] {
        let (output, events) = stream(&scrubber, None, representation.as_bytes().chunks(1));
        assert_eq!(output, MARKER.as_bytes());
        assert_event_count(&events, 1);
    }
}

#[test]
fn legacy_carry_also_protects_encoded_exact_matches() {
    let scrubber = scrubber(&[("FIXTURE", FIXTURE)]);
    for representation in representations(FIXTURE) {
        let mut carry = Vec::new();
        let mut output = Vec::new();
        for byte in representation.as_bytes().chunks(1) {
            output.extend(scrubber.scrub_chunk(None, &mut carry, byte).0);
        }
        output.extend(scrubber.flush_carry(None, carry).0);
        assert_eq!(output, MARKER.as_bytes());
    }
}

#[tokio::test]
async fn loopback_proxy_scrubs_encoded_upstream_sse_echoes() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, StreamBody};
    use hyper::body::{Frame, Incoming};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use phantom_proxy::{
        CredentialProfile, Interceptor, ProxyConfig, ProxyServer, ServiceRegistry, ServiceRoute,
    };
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::net::TcpListener;

    // ASCII-only synthetic fixture is valid in the injected HTTP header.
    const UPSTREAM_FIXTURE: &str = "FAKE-echo+/only% fixture~";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let upstream_seen = seen.clone();
    let upstream = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        http1::Builder::new()
            .serve_connection(
                TokioIo::new(socket),
                service_fn(move |request: Request<Incoming>| {
                    let credential = request.headers()["x-fixture"].to_str().unwrap().to_string();
                    upstream_seen.lock().unwrap().push(credential.clone());
                    async move {
                        let forms = representations(&credential);
                        let body = format!("data: {}\n\n", forms.join("|"));
                        let frames: Vec<Result<Frame<Bytes>, Infallible>> = body
                            .into_bytes()
                            .into_iter()
                            .map(|byte| Ok(Frame::data(Bytes::from(vec![byte]))))
                            .collect();
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("content-type", "text/event-stream")
                                .body(StreamBody::new(tokio_stream::iter(frames)).boxed())
                                .unwrap(),
                        )
                    }
                }),
            )
            .await
            .unwrap();
    });

    let mut registry = ServiceRegistry::new();
    registry.add_route(ServiceRoute {
        name: "fixture".to_string(),
        target_base: format!("http://127.0.0.1:{upstream_port}"),
        secret_key: "FIXTURE".to_string(),
        header: "x-fixture".to_string(),
        header_format: "{secret}".to_string(),
        credential_profile: CredentialProfile::Standard,
        sdk_base_path: None,
    });
    let proxy_token = ProxyServer::generate_proxy_token();
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: proxy_token.clone(),
            ..ProxyConfig::default()
        },
        registry,
        Interceptor::new_with_named(
            HashMap::from([(
                "synthetic-fixture-placeholder".to_string(),
                UPSTREAM_FIXTURE.to_string(),
            )]),
            HashMap::from([("FIXTURE".to_string(), UPSTREAM_FIXTURE.to_string())]),
        ),
    )
    .await
    .unwrap();
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{}/fixture/echo", proxy.port()))
        .header("x-phantom-proxy-token", &proxy_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let output = response.bytes().await.unwrap();
    let expected = format!(
        "data: {}\n\n",
        vec![MARKER; representations(UPSTREAM_FIXTURE).len()].join("|")
    );
    assert_eq!(output.as_ref(), expected.as_bytes());
    assert_eq!(*seen.lock().unwrap(), vec![UPSTREAM_FIXTURE.to_string()]);
    proxy.shutdown().await;
    upstream.abort();
}
