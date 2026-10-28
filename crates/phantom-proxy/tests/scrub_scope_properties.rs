//! Deterministic fuzz-style properties. All credential-shaped fixtures are FAKE
//! and constructed at runtime; failures identify seeds, never body contents.
#![allow(deprecated)]

use base64::{engine::general_purpose::STANDARD, Engine};
use phantom_proxy::body_scope::{
    scoped_body_replace, scoped_body_replace_for_secret, stream_replace_flush, stream_replace_frame,
};
use phantom_proxy::{Interceptor, ResponseScrubber, StreamingScrubState};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::collections::HashMap;

const TYPES: &[Option<&str>] = &[
    None,
    Some("application/octet-stream"),
    Some("application/json"),
    Some("text/plain; charset=utf-8"),
    Some("text/event-stream"),
    Some("application/x-www-form-urlencoded"),
    Some("multipart/form-data; boundary=FAKE"),
];

fn fake_secret() -> String {
    format!("FAKE:{}:fixture", "0123456789abcdef".repeat(3))
}

fn fake_mapping() -> String {
    format!("phm_{}", hex::encode("FAKE".repeat(8)))
}

fn scrubber() -> ResponseScrubber {
    ResponseScrubber::from_named_map(&HashMap::from([("FAKE_KEY".into(), fake_secret())]))
}

fn stream(
    scrubber: &ResponseScrubber,
    ct: Option<&str>,
    body: &[u8],
    cuts: &[usize],
) -> (Vec<u8>, bool) {
    let mut state = StreamingScrubState::new();
    let mut output = Vec::new();
    let mut hit = false;
    let mut start = 0;
    for end in cuts.iter().copied().chain(std::iter::once(body.len())) {
        let (ready, event) = scrubber.scrub_stream_chunk(ct, &mut state, &body[start..end]);
        output.extend(ready);
        hit |= event.scrubbed;
        assert!(state.buffered_len() <= scrubber.stream_buffer_bound());
        start = end;
    }
    let (tail, event) = scrubber.finish_stream(ct, state);
    output.extend(tail);
    (output, hit | event.scrubbed)
}

fn cuts(rng: &mut StdRng, len: usize) -> Vec<usize> {
    let mut result = vec![0, 0]; // Empty transport frames must be harmless.
    let mut offset = 0;
    while offset < len {
        offset = (offset + rng.gen_range(1..=97)).min(len);
        result.push(offset);
    }
    result
}

#[test]
fn every_pair_of_boundaries_redacts_managed_and_unmanaged_fake_values() {
    for (secret, scanner) in [
        (fake_secret(), scrubber()),
        {
            let unicode = format!("FAKE:{}:☃:終", "boundary".repeat(3));
            let scanner = ResponseScrubber::from_named_map(&HashMap::from([(
                "FAKE_UNICODE".into(),
                unicode.clone(),
            )]));
            (unicode, scanner)
        },
        (
            format!("sk-{}", "FAKE".repeat(8)),
            ResponseScrubber::from_named_map(&HashMap::new()),
        ),
    ] {
        let body = format!("before|{secret}|after").into_bytes();
        let (expected, event) = scanner.scrub_buffered(None, &body);
        assert!(event.scrubbed);
        assert!(!expected
            .windows(secret.len())
            .any(|w| w == secret.as_bytes()));
        for first in 0..=body.len() {
            for second in first..=body.len() {
                let (actual, hit) = stream(&scanner, None, &body, &[0, first, second, second]);
                assert!(hit, "missing event at {first}/{second}");
                assert!(actual == expected, "partition mismatch at {first}/{second}");
            }
        }
    }
}

#[test]
fn seeded_mixed_byte_streams_preserve_surroundings_and_redact_exact_values() {
    let scanner = scrubber();
    let secret = fake_secret();
    let (marker, event) = scanner.scrub_buffered(None, secret.as_bytes());
    assert!(event.scrubbed);
    for seed in 0..128 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut body = Vec::new();
        let mut expected = Vec::new();
        for _ in 0..rng.gen_range(1..=8) {
            // High bytes, NUL, split UTF-8, and SSE delimiters around raw values.
            // This alphabet cannot accidentally form another credential.
            let mut noise: Vec<u8> = (0..rng.gen_range(0..128))
                .map(|_| rng.gen_range(128..=255))
                .collect();
            noise.extend_from_slice("\0☃\r\ndata: |".as_bytes());
            body.extend_from_slice(&noise);
            expected.extend_from_slice(&noise);
            body.extend_from_slice(secret.as_bytes());
            expected.extend_from_slice(&marker);
            body.push(b'|');
            expected.push(b'|');
        }
        let schedule = cuts(&mut rng, body.len());
        for &ct in TYPES {
            let (actual, hit) = stream(&scanner, ct, &body, &schedule);
            assert!(hit, "missing event for seed {seed}");
            assert!(actual == expected, "mixed-byte mismatch for seed {seed}");
        }
    }
}

#[test]
fn incomplete_candidates_and_arbitrary_clean_bytes_survive_eof() {
    let scanner = scrubber();
    let secret = fake_secret();
    // Short prefixes stay below both exact and partial-run detection thresholds.
    for len in 0..8 {
        let body = &secret.as_bytes()[..len];
        let (actual, hit) = stream(&scanner, None, body, &(0..=len).collect::<Vec<_>>());
        assert!(actual == body);
        assert!(!hit);
    }
    let empty = ResponseScrubber::from_named_map(&HashMap::new());
    for seed in 0..128 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut body = vec![0; rng.gen_range(0..4096)];
        rng.fill_bytes(&mut body);
        // Differential oracle retains any real format hits in arbitrary bytes.
        let (expected, event) = empty.scrub_buffered(None, &body);
        let (actual, hit) = stream(&empty, None, &body, &cuts(&mut rng, body.len()));
        assert!(
            actual == expected,
            "arbitrary-byte mismatch for seed {seed}"
        );
        assert_eq!(hit, event.scrubbed, "event mismatch for seed {seed}");
    }
}

fn assert_request_inert(body: &[u8], schedule: &[usize]) {
    let mapping = fake_mapping();
    let interceptor = Interceptor::new(HashMap::from([(mapping, fake_secret())]));
    for &ct in TYPES {
        let (actual, replaced) = scoped_body_replace(&interceptor, ct, body);
        assert!(!replaced);
        assert!(actual == body);
        for key in ["FAKE_KEY", "", "unknown"] {
            let (actual, replaced) = scoped_body_replace_for_secret(&interceptor, key, ct, body);
            assert!(!replaced);
            assert!(actual == body);
        }
    }
    let mut carry = b"FAKE preexisting carry|".to_vec();
    let mut actual = Vec::new();
    let mut start = 0;
    for end in schedule.iter().copied().chain(std::iter::once(body.len())) {
        actual.extend(stream_replace_frame(
            &interceptor,
            &mut carry,
            &body[start..end],
        ));
        assert!(carry.is_empty());
        start = end;
    }
    actual.extend(stream_replace_flush(&interceptor, carry));
    let expected = [b"FAKE preexisting carry|".as_slice(), body].concat();
    assert!(actual == expected);
    assert!(stream_replace_flush(&interceptor, body.to_vec()) == body);
}

#[test]
fn request_mixed_encodings_and_arbitrary_partitions_never_resolve() {
    let mapping = fake_mapping();
    let encoded = STANDARD.encode(&mapping);
    let percent: String = mapping.bytes().map(|b| format!("%{b:02X}")).collect();
    let escaped: String = mapping.bytes().map(|b| format!("\\u{b:04x}")).collect();
    for seed in 0..64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut body = vec![0; rng.gen_range(0..2048)];
        rng.fill_bytes(&mut body);
        body.extend_from_slice(format!("{mapping}|{encoded}|{percent}|{escaped}").as_bytes());
        body.extend(mapping.encode_utf16().flat_map(u16::to_le_bytes));
        assert_request_inert(&body, &cuts(&mut rng, body.len()));
    }
}

// RFC 1952 gzip member with stored DEFLATE blocks, built without a new dependency.
// Request pass-through must preserve the header, payload, CRC, and size trailer.
fn fake_gzip(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    let count = payload.len().div_ceil(65535);
    for (i, block) in payload.chunks(65535).enumerate() {
        out.push(u8::from(i + 1 == count));
        let len = block.len() as u16;
        out.extend(len.to_le_bytes());
        out.extend((!len).to_le_bytes());
        out.extend(block);
    }
    let mut crc = !0u32;
    for byte in payload {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    out.extend((!crc).to_le_bytes());
    out.extend((payload.len() as u32).to_le_bytes());
    out
}

#[test]
fn gzip_request_body_is_byte_identical_across_header_block_and_trailer_splits() {
    let payload = format!("FAKE gzip payload|{}", fake_mapping());
    let body = fake_gzip(payload.as_bytes());
    for split in 0..=body.len() {
        assert_request_inert(&body, &[0, split, split]);
    }
}

#[test]
fn multi_megabyte_bodies_keep_request_bytes_and_bound_response_carry() {
    let mut body = vec![b'!'; 4 * 1024 * 1024];
    let secret = fake_secret();
    for offset in [0, 65530, 2 * 1024 * 1024, body.len() - secret.len()] {
        body[offset..offset + secret.len()].copy_from_slice(secret.as_bytes());
    }
    let mapping = fake_mapping();
    body[8190..8190 + mapping.len()].copy_from_slice(mapping.as_bytes());
    let schedule: Vec<_> = (0..body.len()).step_by(4093).collect();
    assert_request_inert(&body, &schedule);
    let compressed = fake_gzip(&body);
    assert_request_inert(
        &compressed,
        &(0..compressed.len()).step_by(65521).collect::<Vec<_>>(),
    );
    let scanner = scrubber();
    let (expected, event) = scanner.scrub_buffered(None, &body);
    let (actual, hit) = stream(&scanner, None, &body, &schedule);
    assert!(event.scrubbed && hit);
    assert!(actual == expected);
    assert!(!actual.windows(secret.len()).any(|w| w == secret.as_bytes()));
}
