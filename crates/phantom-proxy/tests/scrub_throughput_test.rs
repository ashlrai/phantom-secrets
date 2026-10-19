//! Throughput check for response scrubbing on a large body. Ignored by
//! default; run in release:
//!   cargo test --release -p phantom-secrets-proxy --test scrub_throughput_test -- --ignored --nocapture

use phantom_proxy::{ResponseScrubber, StreamingScrubState};
use std::collections::HashMap;
use std::time::Instant;

const OPENAI_REAL: &str = "sk-proj-FAKEkey0echo1test2ONLY3abcdefghijklmnopqrstuvwx";
const ANTHROPIC_REAL: &str = "sk-ant-api03-FAKEkey9echo8test7ONLY6zyxwvutsrqponmlkjihgfe";

/// About 8 MiB of SSE-shaped text with no secrets in it.
fn large_sse_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(8 * 1024 * 1024 + 256);
    let mut i: u64 = 0;
    while body.len() < 8 * 1024 * 1024 {
        i += 1;
        body.extend_from_slice(
            format!(
                "data: {{\"id\":\"chatcmpl-{i:08}\",\"choices\":[{{\"delta\":{{\"content\":\"token {} of the reply, plain words only\"}}}}]}}\n\n",
                i.wrapping_mul(2654435761) % 100000
            )
            .as_bytes(),
        );
    }
    body
}

fn scrubber() -> ResponseScrubber {
    let mut named = HashMap::new();
    named.insert("OPENAI_API_KEY".to_string(), OPENAI_REAL.to_string());
    named.insert("ANTHROPIC_API_KEY".to_string(), ANTHROPIC_REAL.to_string());
    ResponseScrubber::from_named_map(&named)
}

#[test]
#[ignore]
fn scrub_throughput_on_8_mib() {
    let body = large_sse_body();
    let mib = body.len() as f64 / (1024.0 * 1024.0);
    let s = scrubber();

    for round in 1..=3 {
        let start = Instant::now();
        let mut state = StreamingScrubState::new();
        let mut out = 0usize;
        for chunk in body.chunks(16 * 1024) {
            out += s
                .scrub_stream_chunk(Some("text/event-stream"), &mut state, chunk)
                .0
                .len();
        }
        out += s.finish_stream(Some("text/event-stream"), state).0.len();
        let stream_secs = start.elapsed().as_secs_f64();
        assert_eq!(
            out,
            body.len(),
            "clean body must pass through unchanged in length"
        );

        let start = Instant::now();
        let (buffered, _) = s.scrub_buffered(Some("application/json"), &body);
        let buffered_secs = start.elapsed().as_secs_f64();
        assert_eq!(buffered.len(), body.len());

        println!(
            "THROUGHPUT round {round}: {mib:.2} MiB; stream {:.1} ms ({:.1} MiB/s); buffered {:.1} ms ({:.1} MiB/s)",
            stream_secs * 1000.0,
            mib / stream_secs,
            buffered_secs * 1000.0,
            mib / buffered_secs
        );
    }
}

/// Worst case for partial matching: about 8 MiB made only of 20-byte runs of
/// a managed key, so every window hits the prefilter and is verified.
#[test]
#[ignore]
fn scrub_throughput_on_8_mib_of_key_fragments() {
    let fragment = format!("{} ", &OPENAI_REAL[10..30]);
    let body = fragment
        .repeat(8 * 1024 * 1024 / fragment.len())
        .into_bytes();
    let mib = body.len() as f64 / (1024.0 * 1024.0);
    let s = scrubber();
    for round in 1..=3 {
        let start = Instant::now();
        let mut state = StreamingScrubState::new();
        let mut out = Vec::new();
        for chunk in body.chunks(16 * 1024) {
            out.extend(
                s.scrub_stream_chunk(Some("text/event-stream"), &mut state, chunk)
                    .0,
            );
        }
        out.extend(s.finish_stream(Some("text/event-stream"), state).0);
        let stream_secs = start.elapsed().as_secs_f64();

        let start = Instant::now();
        let (buffered, _) = s.scrub_buffered(Some("text/plain"), &body);
        let buffered_secs = start.elapsed().as_secs_f64();

        let leaked = String::from_utf8_lossy(&out).contains(&OPENAI_REAL[10..22])
            || String::from_utf8_lossy(&buffered).contains(&OPENAI_REAL[10..22]);
        println!(
            "WORSTCASE round {round}: {mib:.2} MiB; stream {:.1} ms ({:.1} MiB/s); buffered {:.1} ms ({:.1} MiB/s); leaked={leaked}",
            stream_secs * 1000.0,
            mib / stream_secs,
            buffered_secs * 1000.0,
            mib / buffered_secs
        );
        assert!(!leaked);
    }
}
