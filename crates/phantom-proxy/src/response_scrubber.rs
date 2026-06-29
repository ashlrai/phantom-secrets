//! Response Secret Scrubber — Active Leak Interception
//!
//! Provides a content-type-aware pipeline that scrubs real secrets from upstream
//! API responses before they reach the AI agent.  The pipeline supports:
//!
//! * **Buffered responses** — JSON, plain-text, and generic bodies are collected,
//!   scanned for vault-registered secrets and known format patterns, then returned
//!   with every hit replaced by `[REDACTED:<pattern>]`.
//! * **Streaming / SSE responses** — each chunk is processed with a carry-buffer
//!   overlap window so secrets split across chunk boundaries are still caught.
//! * **SSE event parsing** — `data:` lines in `text/event-stream` bodies are
//!   scrubbed individually so partial-event delimiters are not corrupted.
//!
//! On any detected leak the scrubber:
//! 1. Logs a `LeakEvent` to the audit trail (with anomaly flag via `LeakSeverity::High`).
//! 2. Replaces the secret value in the response body.
//! 3. Emits a warning to proxy stderr so the developer sees it immediately.

use std::collections::HashMap;

use crate::interceptor::ResponseLeakAnalyzer;
use phantom_core::audit::{LeakEvent, LeakSeverity};
use tracing::warn;

// ────────────────────────────────────────────────────────────────────────────
// Content-type helpers
// ────────────────────────────────────────────────────────────────────────────

/// Classify a Content-Type header value into what the scrubber needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentKind {
    /// `text/event-stream` — SSE; parse `data:` lines individually.
    Sse,
    /// Any JSON variant (`application/json`, `application/*+json`, …).
    Json,
    /// `text/*` that is not SSE.
    Text,
    /// Binary or unknown — still scrub with vault-value byte scan.
    Other,
}

impl ContentKind {
    pub fn from_header(content_type: Option<&str>) -> Self {
        let ct = match content_type {
            Some(v) => v,
            None => return ContentKind::Other,
        };
        // Only look at the mime-type part (before ';')
        let mime = ct.split(';').next().unwrap_or(ct).trim();
        if mime.eq_ignore_ascii_case("text/event-stream") {
            ContentKind::Sse
        } else if mime.eq_ignore_ascii_case("application/json")
            || mime.ends_with("+json")
            || mime.starts_with("application/json")
        {
            ContentKind::Json
        } else if mime.starts_with("text/") {
            ContentKind::Text
        } else {
            ContentKind::Other
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ScrubEvent — what the scrubber reports back to the caller
// ────────────────────────────────────────────────────────────────────────────

/// Summary of a single scrub operation on a response body or chunk.
#[derive(Debug, Clone)]
pub struct ScrubEvent {
    /// True when at least one secret was removed.
    pub scrubbed: bool,
    /// Audit events for each distinct (pattern × location) leak found.
    pub leak_events: Vec<LeakEvent>,
}

impl ScrubEvent {
    fn clean() -> Self {
        Self {
            scrubbed: false,
            leak_events: Vec::new(),
        }
    }

    fn from_events(events: Vec<LeakEvent>) -> Self {
        let scrubbed = !events.is_empty();
        Self {
            scrubbed,
            leak_events: events,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ResponseScrubber
// ────────────────────────────────────────────────────────────────────────────

/// Real-time response scrubber.  Build once per proxy request from the active
/// vault mapping; call [`scrub_buffered`] or the streaming helpers as chunks
/// arrive.
pub struct ResponseScrubber {
    analyzer: ResponseLeakAnalyzer,
    /// Maximum byte-length of any registered secret value — used to size the
    /// streaming overlap (carry) window.
    max_secret_len: usize,
}

impl ResponseScrubber {
    /// Build from the token→secret mapping used by [`Interceptor::new`].
    pub fn from_token_map(token_to_secret: &HashMap<String, String>) -> Self {
        let max_secret_len = token_to_secret.values().map(|v| v.len()).max().unwrap_or(0);
        Self {
            analyzer: ResponseLeakAnalyzer::from_token_map(token_to_secret),
            max_secret_len,
        }
    }

    /// Build from a name→secret mapping (human-readable key names in leak events).
    pub fn from_named_map(named_secrets: &HashMap<String, String>) -> Self {
        let max_secret_len = named_secrets.values().map(|v| v.len()).max().unwrap_or(0);
        Self {
            analyzer: ResponseLeakAnalyzer::new(named_secrets),
            max_secret_len,
        }
    }

    /// The carry-buffer overlap size needed for streaming scrubbing.
    /// Callers that manage their own carry buffer should retain this many bytes
    /// between chunks.
    pub fn overlap_len(&self) -> usize {
        self.max_secret_len.saturating_sub(1)
    }

    // ── Buffered scrub ────────────────────────────────────────────────────────

    /// Scrub a fully-buffered response body.
    ///
    /// `content_type` drives whether SSE line-by-line parsing is used.  For
    /// JSON and plain-text the body is scanned as a single string.
    ///
    /// Returns `(scrubbed_body_bytes, ScrubEvent)`.
    pub fn scrub_buffered(
        &self,
        content_type: Option<&str>,
        body: &[u8],
    ) -> (Vec<u8>, ScrubEvent) {
        if body.is_empty() {
            return (Vec::new(), ScrubEvent::clean());
        }

        let kind = ContentKind::from_header(content_type);

        let (scrubbed, events) = match kind {
            ContentKind::Sse => self.scrub_sse_body(body),
            _ => self.analyzer.analyze_body(body),
        };

        let event = ScrubEvent::from_events(events.clone());

        // Emit audit + stderr warnings for every detected leak.
        emit_leak_warnings(&events, content_type);

        (scrubbed, event)
    }

    // ── Streaming scrub ───────────────────────────────────────────────────────

    /// Process one chunk from a streaming response.
    ///
    /// `carry` is the overlap buffer from the previous call; it is prepended
    /// to `chunk` before scanning, and updated to hold the last `overlap_len()`
    /// bytes of the scrubbed result.
    ///
    /// Returns `(bytes_ready_to_emit, ScrubEvent)`.
    pub fn scrub_chunk(
        &self,
        content_type: Option<&str>,
        carry: &mut Vec<u8>,
        chunk: &[u8],
    ) -> (Vec<u8>, ScrubEvent) {
        // Combine carry + new chunk.
        let mut combined = Vec::with_capacity(carry.len() + chunk.len());
        combined.extend_from_slice(carry);
        combined.extend_from_slice(chunk);

        let kind = ContentKind::from_header(content_type);

        let (scrubbed, events) = match kind {
            ContentKind::Sse => self.scrub_sse_body(&combined),
            _ => self.analyzer.analyze_body(&combined),
        };

        let overlap = self.overlap_len();

        let to_emit = if overlap > 0 && scrubbed.len() > overlap {
            let emit_end = scrubbed.len() - overlap;
            *carry = scrubbed[emit_end..].to_vec();
            scrubbed[..emit_end].to_vec()
        } else if overlap > 0 {
            // Entire result fits in the overlap window — carry it all.
            *carry = scrubbed;
            Vec::new()
        } else {
            carry.clear();
            scrubbed
        };

        let event = ScrubEvent::from_events(events.clone());
        emit_leak_warnings(&events, content_type);

        (to_emit, event)
    }

    /// Flush the remaining carry buffer at end-of-stream.
    ///
    /// Returns `(final_bytes, ScrubEvent)`.
    pub fn flush_carry(
        &self,
        content_type: Option<&str>,
        carry: Vec<u8>,
    ) -> (Vec<u8>, ScrubEvent) {
        if carry.is_empty() {
            return (Vec::new(), ScrubEvent::clean());
        }
        let kind = ContentKind::from_header(content_type);
        let (scrubbed, events) = match kind {
            ContentKind::Sse => self.scrub_sse_body(&carry),
            _ => self.analyzer.analyze_body(&carry),
        };
        let event = ScrubEvent::from_events(events.clone());
        emit_leak_warnings(&events, content_type);
        (scrubbed, event)
    }

    // ── SSE parsing ───────────────────────────────────────────────────────────

    /// Scrub an SSE body (or chunk) by scanning each `data:` line individually.
    ///
    /// The SSE wire format is `data: <payload>\n\n`.  We split on `\n`, scrub
    /// lines that start with `data:`, and reassemble verbatim.
    fn scrub_sse_body(&self, body: &[u8]) -> (Vec<u8>, Vec<LeakEvent>) {
        let Ok(text) = std::str::from_utf8(body) else {
            // Non-UTF-8 chunk: fall back to byte-level vault scan via analyze_body.
            return self.analyzer.analyze_body(body);
        };

        let mut all_events: Vec<LeakEvent> = Vec::new();
        let mut output = String::with_capacity(text.len());

        // `split('\n')` on "a\nb\n" yields ["a", "b", ""] — three items.
        // The trailing empty string is an artefact of the final '\n'; we must
        // not add another '\n' after it or we produce one extra newline.
        // Strategy: add '\n' *before* each line except the first, then handle
        // the trailing sentinel empty-string by simply skipping it.
        let lines: Vec<&str> = text.split('\n').collect();
        let n = lines.len();
        // Determine the real last index: if the input ends with '\n' the last
        // element of `lines` is always "" and should not be emitted as a line.
        let last_real = if text.ends_with('\n') && n > 0 { n - 1 } else { n };
        for i in 0..last_real {
            let line = lines[i];
            if i > 0 {
                output.push('\n');
            }
            if let Some(payload) = line.strip_prefix("data:") {
                let (scrubbed_payload, events) =
                    self.analyzer.analyze_body(payload.as_bytes());
                all_events.extend(events);
                output.push_str("data:");
                output.push_str(
                    std::str::from_utf8(&scrubbed_payload).unwrap_or(payload),
                );
            } else {
                // Non-data lines (event:, id:, retry:, comments, blank) pass through.
                // Still scan them in case a secret slipped into an event: field.
                let (scrubbed_line, events) =
                    self.analyzer.analyze_body(line.as_bytes());
                all_events.extend(events);
                output.push_str(
                    std::str::from_utf8(&scrubbed_line).unwrap_or(line),
                );
            }
        }
        // Restore the trailing '\n' if the original had one.
        if text.ends_with('\n') {
            output.push('\n');
        }

        (output.into_bytes(), all_events)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Audit + stderr helpers
// ────────────────────────────────────────────────────────────────────────────

/// Emit audit log entries and stderr warnings for every leak event.
///
/// High-severity events (vault-confirmed) are flagged as anomalies in the
/// audit trail via `LeakEvent::emit()`.  All events produce a `warn!` log
/// line so the developer sees the interception immediately.
fn emit_leak_warnings(events: &[LeakEvent], content_type: Option<&str>) {
    for event in events {
        // Persist to structured audit log.
        event.emit();

        // Human-readable stderr warning for the developer.
        let severity_label = match event.severity {
            LeakSeverity::High => "HIGH — vault-confirmed credential",
            LeakSeverity::Medium => "MEDIUM — pattern match (unregistered secret format)",
        };
        warn!(
            "[phantom-proxy] RESPONSE LEAK INTERCEPTED: {} | pattern={} | location={} | matches={} | content_type={}{}",
            severity_label,
            event.pattern,
            event.location.as_label(),
            event.match_count,
            content_type.unwrap_or("<unknown>"),
            event.secret_name.as_deref()
                .map(|n| format!(" | secret_key={n}"))
                .unwrap_or_default(),
        );

        // Mirror to stderr directly — important when tracing subscriber is not
        // configured (e.g. during library unit tests).
        eprintln!(
            "[phantom-proxy] SECURITY WARNING: response leak intercepted \
             (severity={}, pattern={}, location={}, matches={}{})",
            match event.severity {
                LeakSeverity::High => "high",
                LeakSeverity::Medium => "medium",
            },
            event.pattern,
            event.location.as_label(),
            event.match_count,
            event.secret_name.as_deref()
                .map(|n| format!(", key={n}"))
                .unwrap_or_default(),
        );
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn scrubber_with(token: &str, secret: &str) -> ResponseScrubber {
        let mut m = HashMap::new();
        m.insert(token.to_string(), secret.to_string());
        ResponseScrubber::from_token_map(&m)
    }

    const PHM: &str = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
    const SECRET: &str = "sk-live-testkey0000111122223333444";

    // ── ContentKind classification ────────────────────────────────────────────

    #[test]
    fn content_kind_sse() {
        assert_eq!(
            ContentKind::from_header(Some("text/event-stream")),
            ContentKind::Sse
        );
        assert_eq!(
            ContentKind::from_header(Some("text/event-stream; charset=utf-8")),
            ContentKind::Sse
        );
    }

    #[test]
    fn content_kind_json() {
        assert_eq!(
            ContentKind::from_header(Some("application/json")),
            ContentKind::Json
        );
        assert_eq!(
            ContentKind::from_header(Some("application/json; charset=utf-8")),
            ContentKind::Json
        );
        assert_eq!(
            ContentKind::from_header(Some("application/vnd.api+json")),
            ContentKind::Json
        );
    }

    #[test]
    fn content_kind_text() {
        assert_eq!(
            ContentKind::from_header(Some("text/plain")),
            ContentKind::Text
        );
    }

    #[test]
    fn content_kind_other() {
        assert_eq!(ContentKind::from_header(None), ContentKind::Other);
        assert_eq!(
            ContentKind::from_header(Some("application/octet-stream")),
            ContentKind::Other
        );
    }

    // ── Buffered JSON response ────────────────────────────────────────────────

    #[test]
    fn scrub_buffered_json_redacts_vault_secret() {
        let scrubber = scrubber_with(PHM, SECRET);
        let body = format!(r#"{{"error":"invalid key: {SECRET}","code":401}}"#);
        let (out, event) = scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
        let out_str = String::from_utf8(out).unwrap();
        assert!(event.scrubbed);
        assert!(!out_str.contains(SECRET), "secret still present: {out_str}");
        assert!(
            out_str.contains("[REDACTED:"),
            "no redaction marker: {out_str}"
        );
    }

    #[test]
    fn scrub_buffered_json_clean_body_untouched() {
        let scrubber = scrubber_with(PHM, SECRET);
        let body = r#"{"message":"hello world","status":"ok"}"#;
        let (out, event) = scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
        assert!(!event.scrubbed);
        assert_eq!(String::from_utf8(out).unwrap(), body);
    }

    /// OpenAI-style JSON error that echoes the real key back.
    #[test]
    fn scrub_buffered_openai_json_response() {
        let secret = "sk-real-openai-key-abcdef123456";
        let token = "phm_bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333";
        let scrubber = scrubber_with(token, secret);

        let body = format!(
            r#"{{"error":{{"message":"Invalid API key: {secret}","type":"invalid_request_error","code":"invalid_api_key"}}}}"#
        );
        let (out, event) =
            scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
        let out_str = String::from_utf8(out).unwrap();

        assert!(event.scrubbed, "expected scrub but got clean");
        assert!(
            !out_str.contains(secret),
            "OpenAI secret leaked through JSON scrubber: {out_str}"
        );
        assert_eq!(event.leak_events.len(), 1);
        assert_eq!(event.leak_events[0].severity, LeakSeverity::High);
    }

    /// Stripe webhook payload containing a live key.
    #[test]
    fn scrub_buffered_stripe_webhook_payload() {
        let secret = "sk_live_abcdefghijklmnopq26x";
        let token = "phm_cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444";
        let scrubber = scrubber_with(token, secret);

        let body = format!(
            r#"{{"id":"evt_xxx","object":"event","data":{{"object":{{"key":"{secret}"}}}}}}"#
        );
        let (out, event) =
            scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
        let out_str = String::from_utf8(out).unwrap();

        assert!(event.scrubbed);
        assert!(
            !out_str.contains(secret),
            "Stripe secret leaked: {out_str}"
        );
        // Pattern-level detection should also catch it (sk_live_*)
        let has_redaction = out_str.contains("[REDACTED:");
        assert!(has_redaction, "no redaction marker in: {out_str}");
    }

    // ── Plain-text response ───────────────────────────────────────────────────

    #[test]
    fn scrub_buffered_plain_text_redacts_secret() {
        let scrubber = scrubber_with(PHM, SECRET);
        let body = format!("Authorization: Bearer {SECRET}");
        let (out, event) =
            scrubber.scrub_buffered(Some("text/plain"), body.as_bytes());
        let out_str = String::from_utf8(out).unwrap();
        assert!(event.scrubbed);
        assert!(!out_str.contains(SECRET));
    }

    // ── SSE event scrubbing ───────────────────────────────────────────────────

    #[test]
    fn scrub_buffered_sse_data_line_redacted() {
        let secret = "sk-sse-secret-key-xyz";
        let token = "phm_dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444eeee5555";
        let scrubber = scrubber_with(token, secret);

        let body = format!(
            "data: {{\"key\":\"{secret}\"}}\n\ndata: {{\"delta\":\"hello\"}}\n\n"
        );
        let (out, event) =
            scrubber.scrub_buffered(Some("text/event-stream"), body.as_bytes());
        let out_str = String::from_utf8(out).unwrap();

        assert!(event.scrubbed, "SSE body not scrubbed");
        assert!(
            !out_str.contains(secret),
            "secret survived SSE scrub: {out_str}"
        );
        // Non-secret data line should be intact
        assert!(
            out_str.contains("delta"),
            "non-secret SSE data lost: {out_str}"
        );
    }

    #[test]
    fn scrub_buffered_sse_clean_events_unchanged() {
        let scrubber = scrubber_with(PHM, SECRET);
        let body = "data: {\"delta\":\"hello\"}\n\ndata: {\"delta\":\" world\"}\n\n";
        let (out, event) = scrubber.scrub_buffered(Some("text/event-stream"), body.as_bytes());
        assert!(!event.scrubbed);
        assert_eq!(String::from_utf8(out).unwrap(), body);
    }

    // ── Streaming chunk scrubbing ─────────────────────────────────────────────

    /// An OpenAI streaming response (SSE) whose secret is split across two chunks.
    #[test]
    fn scrub_streaming_openai_sse_split_secret() {
        let secret = "sk-streaming-live-key-9999";
        let token = "phm_eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666";
        let scrubber = scrubber_with(token, secret);

        let full = format!("data: {{\"key\":\"{secret}\"}}\n\n");
        let split = secret.len() / 2;
        // Split mid-secret
        let chunk1 = format!("data: {{\"key\":\"{}\"", &secret[..split]);
        let chunk2 = format!("{}\"}}\n\n", &secret[split..]);

        let mut carry = Vec::new();
        let mut emitted = Vec::new();

        let (part1, _) = scrubber.scrub_chunk(Some("text/event-stream"), &mut carry, chunk1.as_bytes());
        emitted.extend_from_slice(&part1);

        let (part2, event2) = scrubber.scrub_chunk(Some("text/event-stream"), &mut carry, chunk2.as_bytes());
        emitted.extend_from_slice(&part2);

        let (tail, _) = scrubber.flush_carry(Some("text/event-stream"), carry);
        emitted.extend_from_slice(&tail);

        let result = String::from_utf8(emitted).unwrap();
        let _ = full; // just to suppress unused warning
        assert!(
            !result.contains(secret),
            "secret survived streaming SSE scrub: {result}"
        );
        // Either the scrub event fired or the carry absorbed it completely — both OK.
        let _ = event2;
    }

    /// A plain-text streaming response with a GitHub token split across chunks.
    #[test]
    fn scrub_streaming_plain_text_split_across_chunks() {
        let secret = "sk-ant-plain-streaming-secret-xxxx";
        let token = "phm_ffff6666aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111";
        let scrubber = scrubber_with(token, secret);

        for split in 1..secret.len() {
            let chunk1 = format!("prefix-{}", &secret[..split]);
            let chunk2 = format!("{}-suffix", &secret[split..]);

            let mut carry = Vec::new();
            let mut emitted = Vec::new();

            let (p1, _) = scrubber.scrub_chunk(Some("text/plain"), &mut carry, chunk1.as_bytes());
            emitted.extend_from_slice(&p1);

            let (p2, _) = scrubber.scrub_chunk(Some("text/plain"), &mut carry, chunk2.as_bytes());
            emitted.extend_from_slice(&p2);

            let (tail, _) = scrubber.flush_carry(Some("text/plain"), carry);
            emitted.extend_from_slice(&tail);

            let result = String::from_utf8(emitted).unwrap();
            assert!(
                !result.contains(secret),
                "secret leaked at split_pos={split}: {result}"
            );
        }
    }

    /// Streaming with no registered secrets — zero-overhead path.
    #[test]
    fn scrub_streaming_no_secrets_passthrough() {
        let scrubber = ResponseScrubber::from_token_map(&HashMap::new());
        let chunk = b"hello world";
        let mut carry = Vec::new();
        let (out, event) = scrubber.scrub_chunk(Some("application/json"), &mut carry, chunk);
        // overlap_len == 0 so everything is emitted immediately
        assert_eq!(out, chunk);
        assert!(!event.scrubbed);
        assert!(carry.is_empty());
    }

    /// Format-pattern match (sk_live_* appearing in a response but NOT registered
    /// in the vault) should still be caught at MEDIUM severity.
    #[test]
    fn scrub_format_pattern_match_medium_severity() {
        let scrubber = ResponseScrubber::from_token_map(&HashMap::new());
        // Use a key value long enough to match the sk_live_ regex (20+ chars after prefix).
        let raw_key = "sk_live_abcdefghijklmnopq32x";
        let body = format!("the key is {raw_key} and more text");
        let (out, event) = scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
        let out_str = String::from_utf8(out).unwrap();
        assert!(event.scrubbed, "format-pattern not detected: {out_str}");
        // The raw key value must be gone (replaced by [REDACTED:sk_live_*]).
        // Note: the redaction marker itself contains "sk_live_" as part of the
        // label, so we check that the full original key is absent.
        assert!(
            !out_str.contains(raw_key),
            "raw sk_live_ key still present: {out_str}"
        );
        assert!(
            out_str.contains("[REDACTED:sk_live_*]"),
            "expected redaction marker: {out_str}"
        );
        let medium = event
            .leak_events
            .iter()
            .any(|e| e.severity == LeakSeverity::Medium);
        assert!(medium, "expected MEDIUM severity event");
    }

    /// phm_ token mismatch: a phantom token appearing in a response body (not
    /// belonging to any vault entry) should be caught by format-pattern match.
    #[test]
    fn scrub_phm_mismatch_in_response() {
        // No secrets registered, but a phm_ token appears raw in response.
        let scrubber = ResponseScrubber::from_token_map(&HashMap::new());
        let phm_token = "phm_".to_string() + &"a".repeat(64);
        let body = format!("leaked token: {phm_token}");
        let (out, event) = scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
        let out_str = String::from_utf8(out).unwrap();
        assert!(event.scrubbed, "phm_ mismatch not detected");
        assert!(!out_str.contains(&phm_token), "phm_ token still present");
    }

    /// GitHub token (ghp_) in a JSON response body.
    #[test]
    fn scrub_github_token_in_json_response() {
        let secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let token = "phm_1111222233334444555566667777888899990000aaaabbbbccccddddeeee1111";
        let scrubber = scrubber_with(token, secret);

        let body = format!(r#"{{"token":"{secret}","user":"octocat"}}"#);
        let (out, event) = scrubber.scrub_buffered(Some("application/json"), body.as_bytes());
        let out_str = String::from_utf8(out).unwrap();

        assert!(event.scrubbed);
        assert!(
            !out_str.contains(secret),
            "GitHub token leaked: {out_str}"
        );
    }

    // ── Integration: malicious MCP exfiltration via response ─────────────────

    /// Simulates a compromised MCP tool that tries to exfiltrate a secret by
    /// embedding it in a JSON response body.  The scrubber must intercept it
    /// before the payload reaches the AI agent.
    #[test]
    fn integration_malicious_mcp_response_exfiltration_blocked() {
        let real_secret = "sk-mcp-exfil-secret-abcdef123456";
        let phantom_token = "phm_2222333344445555666677778888999900001111222233334444555566667777";

        let scrubber = scrubber_with(phantom_token, real_secret);

        // The malicious MCP tool crafts a response that includes the real secret.
        let malicious_response = format!(
            r#"{{
                "tool_result": "success",
                "debug_info": {{
                    "api_key_used": "{real_secret}",
                    "endpoint": "https://api.openai.com/v1/chat/completions"
                }},
                "data": "some benign payload"
            }}"#
        );

        let (scrubbed, event) = scrubber.scrub_buffered(
            Some("application/json"),
            malicious_response.as_bytes(),
        );
        let scrubbed_str = String::from_utf8(scrubbed).unwrap();

        // The real secret must NOT reach the AI agent.
        assert!(
            !scrubbed_str.contains(real_secret),
            "SECURITY FAILURE: MCP exfiltration not blocked. Secret reached agent: {scrubbed_str}"
        );

        // The leak event must be recorded.
        assert!(
            event.scrubbed,
            "Scrubber did not flag MCP exfiltration attempt"
        );
        assert!(
            !event.leak_events.is_empty(),
            "No LeakEvent emitted for MCP exfiltration"
        );

        // Benign data must be preserved.
        assert!(
            scrubbed_str.contains("some benign payload"),
            "Benign response data was incorrectly removed: {scrubbed_str}"
        );

        // High severity because it's a vault-confirmed key.
        let high = event
            .leak_events
            .iter()
            .any(|e| e.severity == LeakSeverity::High);
        assert!(
            high,
            "Expected HIGH severity for vault-confirmed exfiltration"
        );
    }

    /// Streaming variant of the MCP exfiltration test — the secret is split
    /// across two SSE chunks to try to bypass chunk-level scrubbing.
    #[test]
    fn integration_malicious_mcp_streaming_exfiltration_blocked() {
        let real_secret = "sk-mcp-stream-secret-xyz789";
        let phantom_token = "phm_3333444455556666777788889999000011112222333344445555666677778888";

        let scrubber = scrubber_with(phantom_token, real_secret);

        // Split the secret across two SSE data chunks.
        let split = real_secret.len() / 2;
        let chunk1 = format!("data: {{\"key\":\"{}", &real_secret[..split]);
        let chunk2 = format!("{}\"}}\n\n", &real_secret[split..]);

        let mut carry = Vec::new();
        let mut all_emitted = Vec::new();

        let (p1, _) =
            scrubber.scrub_chunk(Some("text/event-stream"), &mut carry, chunk1.as_bytes());
        all_emitted.extend_from_slice(&p1);

        let (p2, _) =
            scrubber.scrub_chunk(Some("text/event-stream"), &mut carry, chunk2.as_bytes());
        all_emitted.extend_from_slice(&p2);

        let (tail, _) = scrubber.flush_carry(Some("text/event-stream"), carry);
        all_emitted.extend_from_slice(&tail);

        let result = String::from_utf8(all_emitted).unwrap();

        assert!(
            !result.contains(real_secret),
            "SECURITY FAILURE: streaming MCP exfiltration not blocked: {result}"
        );
    }

    // ── Empty / edge cases ────────────────────────────────────────────────────

    #[test]
    fn scrub_empty_body_is_clean() {
        let scrubber = scrubber_with(PHM, SECRET);
        let (out, event) = scrubber.scrub_buffered(Some("application/json"), b"");
        assert!(out.is_empty());
        assert!(!event.scrubbed);
    }

    #[test]
    fn scrub_non_utf8_binary_body() {
        let scrubber = scrubber_with(PHM, SECRET);
        let mut body = vec![0xFFu8, 0xFEu8, 0x00u8];
        body.extend_from_slice(SECRET.as_bytes());
        body.push(0x01);
        // Should not panic; vault-match still fires via byte scan.
        let (out, event) = scrubber.scrub_buffered(Some("application/octet-stream"), &body);
        assert!(event.scrubbed, "vault secret in binary body not scrubbed");
        assert!(
            !out.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
            "secret still present in binary body"
        );
    }
}
