//! Partial-run redaction in ResponseScrubber: any run of 12 or more
//! consecutive bytes of a token-like managed value is redacted in buffered
//! bodies, headers and streams (including runs split across chunks), while
//! masked displays, short runs, and non-token values keep their text.

use phantom_proxy::{ResponseScrubber, StreamingScrubState};
use std::collections::HashMap;

/// Opaque fake key: no vendor prefix, so no format regex can help.
const OPAQUE: &str = "Q7fakeZ2opaque9KEYm4onlyX8testW3vR6pL1";
const ANTHROPIC_SHAPE: &str = "sk-ant-api03-FAKEkey9echo8test7ONLY6zyxwvutsrqponmlkjihgfe";
const DB_URL: &str = "postgres://app:FAKEpassword@localhost:5432/appdb";
const SHORT: &str = "FAKEshort12345";

fn scrubber(values: &[(&str, &str)]) -> ResponseScrubber {
    let named: HashMap<String, String> = values
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    ResponseScrubber::from_named_map(&named)
}

fn stream(s: &ResponseScrubber, body: &[u8], chunk: usize) -> Vec<u8> {
    let mut state = StreamingScrubState::new();
    let mut out = Vec::new();
    for piece in body.chunks(chunk) {
        out.extend(
            s.scrub_stream_chunk(Some("text/event-stream"), &mut state, piece)
                .0,
        );
        assert!(state.buffered_len() <= s.stream_buffer_bound());
    }
    out.extend(s.finish_stream(Some("text/event-stream"), state).0);
    out
}

fn has_run(text: &str, secret: &str, min: usize) -> bool {
    (0..=secret.len().saturating_sub(min)).any(|i| text.contains(&secret[i..i + min]))
}

#[test]
fn opaque_key_halves_and_middle_are_redacted_in_buffered_and_header() {
    let s = scrubber(&[("OPAQUE_KEY", OPAQUE)]);
    let half = OPAQUE.len() / 2;
    for frag in [
        &OPAQUE[..half],
        &OPAQUE[half..],
        &OPAQUE[half - 6..half + 6],
    ] {
        let body = format!(r#"{{"error":{{"message":"bad key {frag} given"}}}}"#);
        let (out, event) = s.scrub_buffered(Some("application/json"), body.as_bytes());
        let out = String::from_utf8(out).unwrap();
        assert!(!has_run(&out, OPAQUE, 12), "{out}");
        assert!(
            out.contains("bad key [REDACTED:vault-secret] given"),
            "{out}"
        );
        assert!(event.scrubbed);

        let (header, _) = s.scrub_header("x-echo", &format!("bad key {frag}"));
        assert_eq!(header, "bad key [REDACTED:vault-secret]");
    }
}

#[test]
fn run_split_across_one_byte_chunks_is_redacted_once() {
    let s = scrubber(&[("OPAQUE_KEY", OPAQUE)]);
    let body = format!("data: {{\"message\":\"key {} end\"}}\n\n", &OPAQUE[3..30]);
    for chunk in [1, 2, 5, 11, 12, 13, 64] {
        let out = String::from_utf8(stream(&s, body.as_bytes(), chunk)).unwrap();
        assert!(!has_run(&out, OPAQUE, 12), "chunk {chunk}: {out}");
        assert_eq!(
            out, "data: {\"message\":\"key [REDACTED:vault-secret] end\"}\n\n",
            "chunk {chunk}"
        );
    }
}

#[test]
fn clean_stream_passes_through_byte_exact_at_any_chunking() {
    let s = scrubber(&[
        ("OPAQUE_KEY", OPAQUE),
        ("ANTHROPIC_API_KEY", ANTHROPIC_SHAPE),
    ]);
    let body = "data: {\"delta\":\"plain words, numbers 0123456789 and sk-ant-api03-...hgfe\"}\n\n"
        .repeat(50);
    for chunk in [1, 7, 11, 12, 4096] {
        assert_eq!(
            stream(&s, body.as_bytes(), chunk),
            body.as_bytes(),
            "chunk {chunk}"
        );
    }
}

#[test]
fn eleven_byte_run_and_masked_form_survive() {
    let s = scrubber(&[
        ("ANTHROPIC_API_KEY", ANTHROPIC_SHAPE),
        ("OPAQUE_KEY", OPAQUE),
    ]);
    let eleven = &OPAQUE[10..21];
    let text = format!("ids {eleven} and sk-ant-api03-...hgfe and sk-ant-api03- alone");
    let (out, event) = s.scrub_buffered(Some("text/plain"), text.as_bytes());
    assert_eq!(String::from_utf8(out).unwrap(), text);
    assert!(!event.scrubbed);
    assert_eq!(stream(&s, text.as_bytes(), 3), text.as_bytes());
}

#[test]
fn connection_strings_and_short_values_are_matched_exactly_only() {
    let s = scrubber(&[("DATABASE_URL", DB_URL), ("SHORT_TOKEN", SHORT)]);
    let text = "connect to localhost:5432/appdb failed; token FAKEshort123 seen";
    let (out, _) = s.scrub_buffered(Some("text/plain"), text.as_bytes());
    assert_eq!(String::from_utf8(out).unwrap(), text);

    // Exact values are still redacted.
    let (out, _) = s.scrub_buffered(Some("text/plain"), format!("{DB_URL} {SHORT}").as_bytes());
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "[REDACTED:vault-secret] [REDACTED:vault-secret]"
    );
}

#[test]
fn legacy_carry_api_loses_no_bytes() {
    let s = scrubber(&[("OPAQUE_KEY", OPAQUE)]);
    let body = format!("data: plain text then {} tail\n\n", &OPAQUE[5..25]);
    let mut carry = Vec::new();
    let mut out = Vec::new();
    for piece in body.as_bytes().chunks(4) {
        out.extend(
            s.scrub_chunk(Some("text/event-stream"), &mut carry, piece)
                .0,
        );
    }
    out.extend(s.flush_carry(Some("text/event-stream"), carry).0);
    let out = String::from_utf8(out).unwrap();
    assert!(out.starts_with("data: plain text then "), "{out}");
    assert!(out.ends_with(" tail\n\n"), "{out}");
    // Per-call flushing cannot see runs split across legacy calls; the typed
    // API (used by the server) can. The legacy path must still never drop or
    // reorder bytes.
    let clean = "data: nothing secret here at all\n\n".repeat(20);
    let mut carry = Vec::new();
    let mut out = Vec::new();
    for piece in clean.as_bytes().chunks(5) {
        out.extend(
            s.scrub_chunk(Some("text/event-stream"), &mut carry, piece)
                .0,
        );
    }
    out.extend(s.flush_carry(Some("text/event-stream"), carry).0);
    assert_eq!(out, clean.as_bytes());
}
