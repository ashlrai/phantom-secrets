//! Regression coverage for value-blind, streaming detection of credentials
//! which are not present in Phantom's managed vault map.
//!
//! These tests deliberately exercise the public streaming API. They make the
//! byte-boundary contract observable without depending on the scrubber's
//! internal state representation.

use phantom_core::audit::{LeakLocation, LeakSeverity};
use phantom_proxy::{ResponseScrubber, ScrubEvent, StreamingScrubState};
use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Family {
    label: &'static str,
    token: String,
    incomplete: String,
    unbounded: bool,
}

fn families() -> Vec<Family> {
    vec![
        Family {
            label: "sk_*",
            token: format!("sk-{}", "A".repeat(28)),
            incomplete: format!("sk-{}", "A".repeat(19)),
            unbounded: true,
        },
        Family {
            label: "sk_live_*",
            token: format!("sk_live_{}", "B".repeat(28)),
            incomplete: format!("sk_live_{}", "B".repeat(19)),
            unbounded: true,
        },
        Family {
            label: "sk_test_*",
            token: format!("sk_test_{}", "C".repeat(28)),
            incomplete: format!("sk_test_{}", "C".repeat(19)),
            unbounded: true,
        },
        Family {
            label: "ghp_*",
            token: format!("ghp_{}", "D".repeat(44)),
            incomplete: format!("ghp_{}", "D".repeat(35)),
            unbounded: true,
        },
        Family {
            label: "github_pat_*",
            token: format!("github_pat_{}", "E".repeat(88)),
            incomplete: format!("github_pat_{}", "E".repeat(79)),
            unbounded: true,
        },
        Family {
            label: "AKIA*",
            token: format!("AKIA{}", "F".repeat(16)),
            incomplete: format!("AKIA{}", "F".repeat(15)),
            unbounded: false,
        },
        Family {
            label: "AIza*",
            token: format!("AIza{}", "G".repeat(35)),
            incomplete: format!("AIza{}", "G".repeat(34)),
            unbounded: false,
        },
        Family {
            label: "xoxb-*",
            token: format!("xoxb-{}", "H".repeat(48)),
            incomplete: format!("xoxb-{}", "H".repeat(39)),
            unbounded: true,
        },
        Family {
            label: "xoxp-*",
            token: format!("xoxp-{}", "J".repeat(48)),
            incomplete: format!("xoxp-{}", "J".repeat(39)),
            unbounded: true,
        },
        Family {
            label: "SG.*",
            token: format!("SG.{}.{}", "K".repeat(22), "L".repeat(43)),
            incomplete: format!("SG.{}.{}", "K".repeat(22), "L".repeat(42)),
            unbounded: false,
        },
        Family {
            label: "AC*",
            token: format!("AC{}", "a".repeat(32)),
            incomplete: format!("AC{}", "a".repeat(31)),
            unbounded: false,
        },
        Family {
            label: "phm_*",
            token: format!("phm_{}", "b".repeat(64)),
            incomplete: format!("phm_{}", "b".repeat(63)),
            unbounded: false,
        },
    ]
}

fn empty_scrubber() -> ResponseScrubber {
    ResponseScrubber::from_token_map(&HashMap::new())
}

fn short_managed_scrubber() -> ResponseScrubber {
    let mappings = HashMap::from([("phm_managed_placeholder".to_string(), "~!".to_string())]);
    ResponseScrubber::from_token_map(&mappings)
}

fn marker(label: &str) -> String {
    format!("[REDACTED:{label}]")
}

fn count_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|part| *part == needle)
        .count()
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    count_subslice(haystack, needle) != 0
}

fn run_stream(
    scrubber: &ResponseScrubber,
    content_type: &str,
    chunks: &[Vec<u8>],
) -> (Vec<u8>, Vec<ScrubEvent>, usize) {
    let mut state = StreamingScrubState::new();
    let mut output = Vec::new();
    let mut events = Vec::new();
    let mut max_buffered = 0;

    for chunk in chunks {
        let (ready, event) = scrubber.scrub_stream_chunk(Some(content_type), &mut state, chunk);
        max_buffered = max_buffered.max(state.buffered_len());
        output.extend_from_slice(&ready);
        events.push(event);
    }

    let (tail, event) = scrubber.finish_stream(Some(content_type), state);
    output.extend_from_slice(&tail);
    events.push(event);
    (output, events, max_buffered)
}

fn assert_medium_event(events: &[ScrubEvent], label: &str, context: &str) {
    let matching: Vec<_> = events
        .iter()
        .flat_map(|event| event.leak_events.iter())
        .filter(|event| event.pattern == label)
        .collect();

    assert!(
        !matching.is_empty(),
        "missing {label} audit event: {context}"
    );
    assert_eq!(
        matching.len(),
        1,
        "credential must emit exactly one {label} audit event: {context}"
    );
    assert!(matching.iter().all(|event| {
        event.severity == LeakSeverity::Medium
            && event.secret_name.is_none()
            && event.location == LeakLocation::Body
            && event.match_count == 1
    }));
    assert!(events.iter().any(|event| event.scrubbed));
}

fn wrapped_body(kind: &str, token: &str) -> (String, usize) {
    let prefix = match kind {
        "text/plain" => "before=",
        "application/json" => r#"{"credential":""#,
        "text/event-stream" => r#"data: {"credential":""#,
        _ => unreachable!(),
    };
    let suffix = match kind {
        "text/plain" => ";after",
        "application/json" => r#"","ok":true}"#,
        "text/event-stream" => "\"}\n\n",
        _ => unreachable!(),
    };
    (format!("{prefix}{token}{suffix}"), prefix.len())
}

#[test]
fn every_unmanaged_family_is_scrubbed_at_every_credential_byte_split() {
    for family in families() {
        for content_type in ["text/plain", "application/json", "text/event-stream"] {
            let (body, token_start) = wrapped_body(content_type, &family.token);

            // Exercise both the zero-managed-secret regression and the case in
            // which the longest managed value is far shorter than an unmanaged
            // candidate. Neither may determine unmanaged look-behind safety.
            for (map_case, scrubber) in [
                ("empty-map", empty_scrubber()),
                ("short-map", short_managed_scrubber()),
            ] {
                for token_split in 1..family.token.len() {
                    let split = token_start + token_split;
                    let chunks = vec![
                        body.as_bytes()[..split].to_vec(),
                        body.as_bytes()[split..].to_vec(),
                    ];
                    let (output, events, _) = run_stream(&scrubber, content_type, &chunks);
                    let context = format!(
                        "family={} content_type={content_type} map={map_case} split={token_split}",
                        family.label
                    );

                    assert!(
                        !contains_subslice(&output, family.token.as_bytes()),
                        "credential survived: {context}; output={}",
                        String::from_utf8_lossy(&output)
                    );
                    assert_eq!(
                        count_subslice(&output, marker(family.label).as_bytes()),
                        1,
                        "redaction marker must appear exactly once: {context}; output={}",
                        String::from_utf8_lossy(&output)
                    );
                    assert_medium_event(&events, family.label, &context);
                }
            }
        }
    }
}

#[test]
fn prefixes_split_across_three_chunks_are_not_released() {
    for family in families() {
        assert!(family.token.len() > 2);
        let chunks = vec![
            family.token.as_bytes()[..1].to_vec(),
            family.token.as_bytes()[1..2].to_vec(),
            family.token.as_bytes()[2..].to_vec(),
            b"!safe-tail".to_vec(),
        ];
        let (output, events, _) = run_stream(&empty_scrubber(), "text/plain", &chunks);
        let context = format!("three-chunk prefix for {}", family.label);

        assert!(
            !contains_subslice(&output, family.token.as_bytes()),
            "{context}"
        );
        assert_eq!(count_subslice(&output, marker(family.label).as_bytes()), 1);
        assert!(output.ends_with(b"!safe-tail"));
        assert_medium_event(&events, family.label, &context);
    }
}

#[test]
fn complete_candidates_are_scrubbed_when_eof_is_the_only_boundary() {
    for family in families() {
        let chunks: Vec<Vec<u8>> = family
            .token
            .as_bytes()
            .chunks(3)
            .map(<[u8]>::to_vec)
            .collect();
        let (output, events, _) = run_stream(&empty_scrubber(), "text/plain", &chunks);
        let context = format!("EOF candidate for {}", family.label);

        assert!(
            !contains_subslice(&output, family.token.as_bytes()),
            "{context}"
        );
        assert_eq!(output, marker(family.label).as_bytes(), "{context}");
        assert_medium_event(&events, family.label, &context);
    }
}

#[test]
fn incomplete_candidates_are_preserved_losslessly_at_eof() {
    for family in families() {
        let chunks: Vec<Vec<u8>> = family
            .incomplete
            .as_bytes()
            .chunks(2)
            .map(<[u8]>::to_vec)
            .collect();
        let (output, events, _) = run_stream(&empty_scrubber(), "text/plain", &chunks);

        assert_eq!(
            output,
            family.incomplete.as_bytes(),
            "incomplete {} candidate was not byte-preserving",
            family.label
        );
        assert!(
            events
                .iter()
                .all(|event| !event.scrubbed && event.leak_events.is_empty()),
            "incomplete {} candidate produced an audit event",
            family.label
        );
    }
}

#[test]
fn adjacent_credentials_each_have_one_marker_and_audit_event() {
    let all = families();
    let mut body = Vec::new();
    for (index, family) in all.iter().enumerate() {
        if index > 0 {
            body.push(b',');
        }
        body.extend_from_slice(family.token.as_bytes());
    }

    let chunks: Vec<Vec<u8>> = body.chunks(7).map(<[u8]>::to_vec).collect();
    let (output, events, _) = run_stream(&short_managed_scrubber(), "text/plain", &chunks);

    for family in all {
        assert!(
            !contains_subslice(&output, family.token.as_bytes()),
            "adjacent {} credential survived",
            family.label
        );
        assert_eq!(
            count_subslice(&output, marker(family.label).as_bytes()),
            1,
            "adjacent {} marker count was not one: {}",
            family.label,
            String::from_utf8_lossy(&output)
        );
        assert_medium_event(&events, family.label, "adjacent credentials");
    }
}

#[test]
fn long_unbounded_candidates_emit_once_suppress_continuations_and_stay_bounded() {
    for family in families().into_iter().filter(|family| family.unbounded) {
        let prefix_len = family
            .token
            .find(|ch: char| ch.is_ascii_uppercase())
            .expect("synthetic continuation begins with an uppercase byte");
        let mut candidate = family.token.as_bytes()[..prefix_len].to_vec();
        candidate.extend(std::iter::repeat_n(b'Q', 128 * 1024));

        let mut body = b"safe-prefix:".to_vec();
        body.extend_from_slice(&candidate);
        body.extend_from_slice(b";safe-suffix");
        let chunks: Vec<Vec<u8>> = body.chunks(257).map(<[u8]>::to_vec).collect();
        let scrubber = empty_scrubber();
        let (output, events, max_buffered) = run_stream(&scrubber, "text/plain", &chunks);
        let context = format!("long unbounded {} candidate", family.label);

        assert!(output.starts_with(b"safe-prefix:"), "{context}");
        assert!(output.ends_with(b";safe-suffix"), "{context}");
        assert_eq!(
            count_subslice(&output, marker(family.label).as_bytes()),
            1,
            "{context}: {}",
            String::from_utf8_lossy(&output)
        );
        assert!(
            !contains_subslice(&output, &candidate),
            "{context} leaked its full candidate"
        );
        assert!(
            !output.contains(&b'Q'),
            "{context} leaked one or more continuation bytes"
        );
        assert!(
            output.len() < 256,
            "{context} emitted suppressed continuation bytes ({} bytes)",
            output.len()
        );
        assert!(
            max_buffered < 4096,
            "{context} retained an unexpectedly large streaming state: {max_buffered} bytes"
        );
        assert_medium_event(&events, family.label, &context);
    }
}

#[test]
fn legacy_vec_carry_wrappers_keep_cross_chunk_protection() {
    for family in [families()[0].clone(), families()[5].clone()] {
        let scrubber = short_managed_scrubber();
        let mut carry = Vec::new();
        let split = family.token.len() / 2;
        let chunks = [
            family.token.as_bytes()[..split].to_vec(),
            family.token.as_bytes()[split..].to_vec(),
            b"!".to_vec(),
        ];
        let mut output = Vec::new();
        let mut events = Vec::new();

        for chunk in chunks {
            let (ready, event) = scrubber.scrub_chunk(Some("text/plain"), &mut carry, &chunk);
            output.extend_from_slice(&ready);
            events.push(event);
        }
        let (tail, event) = scrubber.flush_carry(Some("text/plain"), carry);
        output.extend_from_slice(&tail);
        events.push(event);

        assert!(!contains_subslice(&output, family.token.as_bytes()));
        assert_eq!(count_subslice(&output, marker(family.label).as_bytes()), 1);
        assert!(output.ends_with(b"!"));
        assert_medium_event(&events, family.label, "legacy Vec carry wrapper");
    }
}

#[test]
fn invalid_utf8_around_unmanaged_credentials_is_preserved_while_token_is_scrubbed() {
    for family in families() {
        let mut body = vec![0xff, 0x80, b'<'];
        let token_start = body.len();
        body.extend_from_slice(family.token.as_bytes());
        body.extend_from_slice(&[b'>', 0xfe, 0x81]);

        let split = token_start + family.token.len() / 2;
        let chunks = vec![
            body[..1].to_vec(),
            body[1..split].to_vec(),
            body[split..].to_vec(),
        ];
        let (output, events, _) =
            run_stream(&empty_scrubber(), "application/octet-stream", &chunks);
        let context = format!("invalid UTF-8 around {}", family.label);

        assert!(output.starts_with(&[0xff, 0x80, b'<']), "{context}");
        assert!(output.ends_with(&[b'>', 0xfe, 0x81]), "{context}");
        assert!(
            !contains_subslice(&output, family.token.as_bytes()),
            "{context}"
        );
        assert_eq!(count_subslice(&output, marker(family.label).as_bytes()), 1);
        assert_medium_event(&events, family.label, &context);
    }
}

#[test]
fn streaming_and_buffered_github_pat_grammar_reject_hyphens_identically() {
    let candidate = format!("github_pat_{}-{}", "E".repeat(40), "F".repeat(40));
    let scrubber = empty_scrubber();

    let (buffered, buffered_event) =
        scrubber.scrub_buffered(Some("text/plain"), candidate.as_bytes());
    let chunks = candidate
        .as_bytes()
        .chunks(13)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let (streamed, stream_events, _) = run_stream(&scrubber, "text/plain", &chunks);

    assert_eq!(buffered, candidate.as_bytes());
    assert!(!buffered_event.scrubbed);
    assert_eq!(streamed, candidate.as_bytes());
    assert!(stream_events
        .iter()
        .all(|event| !event.scrubbed && event.leak_events.is_empty()));
}

#[test]
fn overlap_len_never_understates_the_typed_streaming_bound() {
    let empty = empty_scrubber();
    assert_eq!(empty.overlap_len(), empty.stream_buffer_bound());
    assert_eq!(empty.overlap_len(), 91);

    let long_secret = "managed-value".repeat(16);
    let managed = ResponseScrubber::from_token_map(&HashMap::from([(
        "phm_managed_placeholder".to_string(),
        long_secret.clone(),
    )]));
    assert_eq!(managed.overlap_len(), managed.stream_buffer_bound());
    assert_eq!(managed.overlap_len(), long_secret.len() - 1);
}
