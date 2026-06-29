use std::collections::HashMap;
use zeroize::Zeroize;

use lazy_static::lazy_static;
use regex::Regex;

use phantom_core::audit::{LeakEvent, LeakLocation, LeakSeverity};

// ──────────────────────────────────────────────────────────────────────────────
// Known secret format patterns (regex pool)
// Each entry: (pattern_label, Regex)
// These cover the most common API key formats emitted by SaaS providers.
// ──────────────────────────────────────────────────────────────────────────────

lazy_static! {
    static ref SECRET_PATTERNS: Vec<(&'static str, Regex)> = vec![
        // OpenAI / Anthropic style (sk- prefix)
        ("sk_*", Regex::new(r"sk-[A-Za-z0-9_\-]{20,}").unwrap()),
        // Stripe live/test keys
        ("sk_live_*", Regex::new(r"sk_live_[A-Za-z0-9]{20,}").unwrap()),
        ("sk_test_*", Regex::new(r"sk_test_[A-Za-z0-9]{20,}").unwrap()),
        // GitHub personal access tokens (classic ghp_ and fine-grained github_pat_)
        ("ghp_*", Regex::new(r"ghp_[A-Za-z0-9]{36,}").unwrap()),
        ("github_pat_*", Regex::new(r"github_pat_[A-Za-z0-9_]{80,}").unwrap()),
        // AWS access keys
        ("AKIA*", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
        // Google API keys
        ("AIza*", Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap()),
        // Slack tokens
        ("xoxb-*", Regex::new(r"xoxb-[0-9A-Za-z\-]{40,}").unwrap()),
        ("xoxp-*", Regex::new(r"xoxp-[0-9A-Za-z\-]{40,}").unwrap()),
        // SendGrid
        ("SG.*", Regex::new(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}").unwrap()),
        // Twilio
        ("AC*", Regex::new(r"AC[0-9a-f]{32}").unwrap()),
        // Phantom tokens themselves (should never appear in responses after scrubbing)
        ("phm_*", Regex::new(r"phm_[0-9a-f]{64}").unwrap()),
    ];
}

// ──────────────────────────────────────────────────────────────────────────────
// ResponseLeakAnalyzer
// ──────────────────────────────────────────────────────────────────────────────

/// Analyzes upstream API responses for real secrets that escaped scrubbing.
///
/// Two detection modes are applied together:
/// 1. **Vault-value match**: compares response content against every real secret
///    in the active injection map. Any hit is HIGH severity and names the key.
/// 2. **Format-pattern match**: scans for well-known API key formats (regex pool).
///    Hits that are NOT in the vault injection map are MEDIUM severity (the
///    response may contain credentials that aren't under Phantom management).
///
/// Detected leaks are replaced with `[REDACTED:<pattern>]` in the returned
/// bytes, and [`LeakEvent`]s are returned for the caller to emit / log.
#[derive(Clone)]
pub struct ResponseLeakAnalyzer {
    /// real_secret_value -> secret_key_name (from vault injection map).
    vault_values: HashMap<String, String>,
}

impl ResponseLeakAnalyzer {
    /// Build an analyzer from the same `token→secret` mapping used by [`Interceptor`].
    /// `named_mappings` maps secret_key_name → real_secret_value.
    pub fn new(named_mappings: &HashMap<String, String>) -> Self {
        // Invert: value → name
        let vault_values = named_mappings
            .iter()
            .map(|(name, value)| (value.clone(), name.clone()))
            .collect();
        Self { vault_values }
    }

    /// Build from a token→secret mapping (same shape as Interceptor::new).
    /// The "name" reported in leak events will be the phantom token string since
    /// the named mapping isn't available in this form. Prefer [`new`] with named
    /// mappings for human-readable key names.
    pub fn from_token_map(token_to_secret: &HashMap<String, String>) -> Self {
        // Here keys are phantom tokens — invert to secret→token.
        let vault_values = token_to_secret
            .iter()
            .map(|(token, secret)| (secret.clone(), token.clone()))
            .collect();
        Self { vault_values }
    }

    /// Analyze `body` bytes for leaked secrets. Returns (scrubbed_body, events).
    ///
    /// All detected leaks are replaced with `[REDACTED:<pattern>]`. A [`LeakEvent`]
    /// is emitted for each distinct (pattern × location) combination found.
    pub fn analyze_body(&self, body: &[u8]) -> (Vec<u8>, Vec<LeakEvent>) {
        let Ok(text) = std::str::from_utf8(body) else {
            // Non-UTF-8 body: run byte-level vault check only.
            let (scrubbed, events) = self.scan_bytes_vault_only(body, LeakLocation::Body);
            return (scrubbed, events);
        };
        let (scrubbed_text, events) = self.scan_str(text, LeakLocation::Body);
        (scrubbed_text.into_bytes(), events)
    }

    /// Analyze a single response header value for leaked secrets.
    /// Returns (scrubbed_value, events).
    pub fn analyze_header(&self, header_name: &str, value: &str) -> (String, Vec<LeakEvent>) {
        self.scan_str(value, LeakLocation::Header(header_name.to_string()))
    }

    /// Analyze the HTTP status line (e.g. forwarded error reasons) for leaks.
    pub fn analyze_status_line(&self, status: &str) -> (String, Vec<LeakEvent>) {
        self.scan_str(status, LeakLocation::StatusLine)
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Core scanner: vault-value match (HIGH) then format-pattern match (MEDIUM).
    fn scan_str(&self, input: &str, location: LeakLocation) -> (String, Vec<LeakEvent>) {
        let mut result = input.to_string();
        let mut events: Vec<LeakEvent> = Vec::new();
        let now = now_unix();

        // 1. Vault-value match (highest priority — confirmed live credential).
        for (secret_val, secret_name) in &self.vault_values {
            if secret_val.is_empty() {
                continue;
            }
            let count = result.matches(secret_val.as_str()).count();
            if count > 0 {
                // Determine a sensible pattern label from the value prefix.
                let pattern = format_pattern_label(secret_val);
                result = result.replace(secret_val.as_str(), &format!("[REDACTED:{}]", pattern));
                events.push(LeakEvent {
                    ts: now,
                    location: location.clone(),
                    severity: LeakSeverity::High,
                    secret_name: Some(secret_name.clone()),
                    pattern,
                    match_count: count,
                });
            }
        }

        // 2. Format-pattern match (catches secrets not yet in vault injection map).
        for (label, re) in SECRET_PATTERNS.iter() {
            // Count remaining matches (after vault replacements above).
            let matches: Vec<_> = re.find_iter(&result).collect();
            if matches.is_empty() {
                continue;
            }
            let count = matches.len();
            // Check whether any of the remaining matches are vault values
            // (they would already have been replaced in step 1; if they're still
            // here they're unrecognised format-only hits → MEDIUM severity).
            let is_vault_confirmed = matches.iter().any(|m| {
                self.vault_values.contains_key(m.as_str())
            });
            let severity = if is_vault_confirmed {
                LeakSeverity::High
            } else {
                LeakSeverity::Medium
            };
            // Replace with [REDACTED:<label>].
            let replacement = format!("[REDACTED:{}]", label);
            let scrubbed = re.replace_all(&result, replacement.as_str()).into_owned();
            if scrubbed != result {
                result = scrubbed;
                // Avoid duplicate events if vault-match already fired for this pattern.
                let already_reported = events.iter().any(|e| &e.pattern == *label);
                if !already_reported {
                    events.push(LeakEvent {
                        ts: now,
                        location: location.clone(),
                        severity,
                        secret_name: None,
                        pattern: label.to_string(),
                        match_count: count,
                    });
                }
            }
        }

        (result, events)
    }

    /// Byte-level vault-only check for non-UTF-8 bodies.
    fn scan_bytes_vault_only(&self, input: &[u8], location: LeakLocation) -> (Vec<u8>, Vec<LeakEvent>) {
        let mut result = input.to_vec();
        let mut events = Vec::new();
        let now = now_unix();

        for (secret_val, secret_name) in &self.vault_values {
            if secret_val.is_empty() {
                continue;
            }
            let needle = secret_val.as_bytes();
            let count = count_occurrences(&result, needle);
            if count > 0 {
                let pattern = format_pattern_label(secret_val);
                let replacement = format!("[REDACTED:{}]", pattern);
                result = replace_bytes(&result, needle, replacement.as_bytes());
                events.push(LeakEvent {
                    ts: now,
                    location: location.clone(),
                    severity: LeakSeverity::High,
                    secret_name: Some(secret_name.clone()),
                    pattern,
                    match_count: count,
                });
            }
        }

        (result, events)
    }
}

/// Derive a concise pattern label from a secret value (e.g. "sk_live_abc…" → "sk_live_*").
fn format_pattern_label(value: &str) -> String {
    // Try to match a known prefix.
    let known_prefixes = [
        "sk_live_", "sk_test_", "sk-", "ghp_", "github_pat_",
        "AKIA", "AIza", "xoxb-", "xoxp-", "SG.", "AC", "phm_",
    ];
    for prefix in &known_prefixes {
        if value.starts_with(prefix) {
            return format!("{}*", prefix);
        }
    }
    // Fallback: first 8 chars + *
    let truncated = if value.len() > 8 { &value[..8] } else { value };
    format!("{}*", truncated)
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut result = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            result.extend_from_slice(replacement);
            i += needle.len();
        } else {
            result.push(haystack[i]);
            i += 1;
        }
    }
    result
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The interceptor replaces phantom tokens with real secrets in HTTP requests,
/// and scrubs real secrets from API responses to prevent leakage.
#[derive(Clone)]
pub struct Interceptor {
    /// phantom_token_string -> real_secret_value (for outgoing requests)
    token_map: HashMap<String, SecretValue>,
    /// env var / secret name -> real_secret_value (for configured header injection)
    named_secrets: HashMap<String, SecretValue>,
    /// real_secret_value -> phantom_token_string (for response scrubbing)
    reverse_map: HashMap<String, String>,
}

/// A secret value that zeroizes itself when dropped.
#[derive(Clone)]
struct SecretValue {
    value: String,
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl Interceptor {
    /// Create a new interceptor with a mapping of phantom tokens to real secrets.
    pub fn new(mappings: HashMap<String, String>) -> Self {
        Self::new_with_named(mappings, HashMap::new())
    }

    /// Create a new interceptor with token mappings and name-addressable
    /// secrets for routes that inject credentials via configured headers.
    pub fn new_with_named(
        mappings: HashMap<String, String>,
        named_mappings: HashMap<String, String>,
    ) -> Self {
        let reverse_map: HashMap<String, String> = mappings
            .iter()
            .map(|(token, secret)| (secret.clone(), token.clone()))
            .collect();
        let token_map = mappings
            .into_iter()
            .map(|(token, secret)| (token, SecretValue { value: secret }))
            .collect();
        let named_secrets = named_mappings
            .into_iter()
            .map(|(name, secret)| (name, SecretValue { value: secret }))
            .collect();
        Self {
            token_map,
            named_secrets,
            reverse_map,
        }
    }

    /// Replace any phantom tokens found in a string with their real values.
    /// Returns the modified string and whether any replacements were made.
    pub fn replace_in_str(&self, input: &str) -> (String, bool) {
        let pairs: Vec<(&str, &str)> = self
            .token_map
            .iter()
            .map(|(token, secret)| (token.as_str(), secret.value.as_str()))
            .collect();
        find_replace_str(input, &pairs)
    }

    /// Replace phantom tokens in a byte buffer (for request bodies).
    /// Returns the modified bytes and whether any replacements were made.
    pub fn replace_in_bytes(&self, input: &[u8]) -> (Vec<u8>, bool) {
        let pairs: Vec<(&str, &str)> = self
            .token_map
            .iter()
            .map(|(token, secret)| (token.as_str(), secret.value.as_str()))
            .collect();
        find_replace_bytes_via_str(input, &pairs)
    }

    /// Format a header value by replacing the {secret} placeholder with the real secret.
    pub fn format_header_value(&self, format: &str, phantom_token: &str) -> Option<String> {
        self.token_map
            .get(phantom_token)
            .map(|secret| format.replace("{secret}", &secret.value))
    }

    /// Format a header value using a configured secret name.
    pub fn format_header_for_secret_key(&self, format: &str, secret_key: &str) -> Option<String> {
        self.named_secrets
            .get(secret_key)
            .map(|secret| format.replace("{secret}", &secret.value))
    }

    /// Look up the real secret for a phantom token.
    pub fn resolve(&self, phantom_token: &str) -> Option<&str> {
        self.token_map.get(phantom_token).map(|s| s.value.as_str())
    }

    /// Check if a value contains any phantom tokens.
    pub fn contains_phantom_token(&self, value: &str) -> bool {
        self.token_map
            .keys()
            .any(|token| value.contains(token.as_str()))
    }

    /// Number of token mappings.
    pub fn len(&self) -> usize {
        self.token_map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.token_map.is_empty()
    }

    /// Maximum length of any real secret in the reverse map.
    /// Used to size the overlap window for streaming response scrubbing.
    pub fn max_secret_len(&self) -> usize {
        self.reverse_map.keys().map(|k| k.len()).max().unwrap_or(0)
    }

    /// Scrub real secrets from a response string, replacing them with phantom tokens.
    /// Prevents API responses from leaking real credentials back to AI agents.
    pub fn scrub_response_str(&self, input: &str) -> (String, bool) {
        let pairs: Vec<(&str, &str)> = self
            .reverse_map
            .iter()
            .map(|(secret, token)| (secret.as_str(), token.as_str()))
            .collect();
        find_replace_str(input, &pairs)
    }

    /// Scrub real secrets from response bytes.
    pub fn scrub_response_bytes(&self, input: &[u8]) -> (Vec<u8>, bool) {
        let pairs: Vec<(&str, &str)> = self
            .reverse_map
            .iter()
            .map(|(secret, token)| (secret.as_str(), token.as_str()))
            .collect();
        find_replace_bytes_via_str(input, &pairs)
    }
}

/// Find-and-replace multiple string patterns. Returns the result and whether any replacement was made.
fn find_replace_str(input: &str, pairs: &[(&str, &str)]) -> (String, bool) {
    let mut result = input.to_string();
    let mut replaced = false;
    for &(needle, replacement) in pairs {
        if result.contains(needle) {
            result = result.replace(needle, replacement);
            replaced = true;
        }
    }
    (result, replaced)
}

/// Find-and-replace in bytes, using the string path for valid UTF-8 and a byte-level
/// scan for non-UTF-8 input.
fn find_replace_bytes_via_str(input: &[u8], pairs: &[(&str, &str)]) -> (Vec<u8>, bool) {
    if let Ok(s) = std::str::from_utf8(input) {
        let (replaced, did) = find_replace_str(s, pairs);
        return (replaced.into_bytes(), did);
    }
    // Non-UTF-8 fallback: byte-level scan
    let byte_pairs: Vec<(&[u8], &[u8])> = pairs
        .iter()
        .map(|(n, r)| (n.as_bytes(), r.as_bytes()))
        .collect();
    let mut result = input.to_vec();
    let mut replaced = false;
    for &(needle, replacement) in &byte_pairs {
        let mut i = 0;
        let mut new_result = Vec::with_capacity(result.len());
        while i < result.len() {
            if i + needle.len() <= result.len() && &result[i..i + needle.len()] == needle {
                new_result.extend_from_slice(replacement);
                i += needle.len();
                replaced = true;
            } else {
                new_result.push(result[i]);
                i += 1;
            }
        }
        result = new_result;
    }
    (result, replaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_interceptor() -> Interceptor {
        let mut mappings = HashMap::new();
        mappings.insert(
            "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222".to_string(),
            "sk-real-openai-key-12345".to_string(),
        );
        mappings.insert(
            "phm_1111222233334444555566667777888899990000aaaabbbbccccddddeeee0000".to_string(),
            "sk-ant-real-anthropic-key".to_string(),
        );
        Interceptor::new(mappings)
    }

    #[test]
    fn test_replace_in_header_value() {
        let interceptor = test_interceptor();
        let (result, replaced) = interceptor.replace_in_str(
            "Bearer phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222",
        );
        assert!(replaced);
        assert_eq!(result, "Bearer sk-real-openai-key-12345");
    }

    #[test]
    fn test_replace_in_body() {
        let interceptor = test_interceptor();
        let body = r#"{"api_key": "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"}"#;
        let (result, replaced) = interceptor.replace_in_bytes(body.as_bytes());
        assert!(replaced);
        let result_str = String::from_utf8(result).unwrap();
        assert!(result_str.contains("sk-real-openai-key-12345"));
        assert!(!result_str.contains("phm_"));
    }

    #[test]
    fn test_no_replacement_needed() {
        let interceptor = test_interceptor();
        let (result, replaced) = interceptor.replace_in_str("Bearer sk-real-key");
        assert!(!replaced);
        assert_eq!(result, "Bearer sk-real-key");
    }

    #[test]
    fn test_contains_phantom_token() {
        let interceptor = test_interceptor();
        assert!(interceptor.contains_phantom_token(
            "Bearer phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
        ));
        assert!(!interceptor.contains_phantom_token("Bearer sk-real-key"));
    }

    #[test]
    fn test_resolve() {
        let interceptor = test_interceptor();
        assert_eq!(
            interceptor
                .resolve("phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"),
            Some("sk-real-openai-key-12345")
        );
        assert_eq!(interceptor.resolve("phm_nonexistent"), None);
    }

    #[test]
    fn test_scrub_response_str() {
        let interceptor = test_interceptor();
        // Simulate an API response that echoes back the real secret
        let response = r#"{"error":"Invalid key: sk-real-openai-key-12345","status":401}"#;
        let (scrubbed, did_scrub) = interceptor.scrub_response_str(response);
        assert!(did_scrub);
        assert!(scrubbed
            .contains("phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"));
        assert!(!scrubbed.contains("sk-real-openai-key-12345"));
    }

    #[test]
    fn test_scrub_response_bytes() {
        let interceptor = test_interceptor();
        let response = b"key echoed: sk-real-openai-key-12345 in response";
        let (scrubbed, did_scrub) = interceptor.scrub_response_bytes(response);
        assert!(did_scrub);
        let scrubbed_str = String::from_utf8(scrubbed).unwrap();
        assert!(!scrubbed_str.contains("sk-real-openai-key-12345"));
        assert!(scrubbed_str.contains("phm_"));
    }

    #[test]
    fn test_scrub_no_secrets_in_response() {
        let interceptor = test_interceptor();
        let response = r#"{"data":"safe content","status":200}"#;
        let (scrubbed, did_scrub) = interceptor.scrub_response_str(response);
        assert!(!did_scrub);
        assert_eq!(scrubbed, response);
    }

    #[test]
    fn test_multiple_replacements_in_body() {
        let interceptor = test_interceptor();
        let body = "key1=phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222&key2=phm_1111222233334444555566667777888899990000aaaabbbbccccddddeeee0000";
        let (result, replaced) = interceptor.replace_in_str(body);
        assert!(replaced);
        assert!(result.contains("sk-real-openai-key-12345"));
        assert!(result.contains("sk-ant-real-anthropic-key"));
        assert!(!result.contains("phm_"));
    }

    #[test]
    fn test_max_secret_len() {
        let interceptor = test_interceptor();
        // "sk-ant-real-anthropic-key" is 25 chars, "sk-real-openai-key-12345" is 24 chars
        assert_eq!(interceptor.max_secret_len(), 25);
    }

    #[test]
    fn test_max_secret_len_empty() {
        let interceptor = Interceptor::new(HashMap::new());
        assert_eq!(interceptor.max_secret_len(), 0);
    }

    #[test]
    fn test_max_secret_len_varied() {
        let mut mappings = HashMap::new();
        mappings.insert("phm_short".to_string(), "abc".to_string());
        mappings.insert(
            "phm_long".to_string(),
            "a-much-longer-secret-value-here".to_string(),
        );
        let interceptor = Interceptor::new(mappings);
        assert_eq!(interceptor.max_secret_len(), 31); // "a-much-longer-secret-value-here"
    }

    /// Simulate streaming scrub with overlap window to verify cross-chunk secret detection.
    #[test]
    fn test_streaming_scrub_overlap_window() {
        let interceptor = test_interceptor();
        let secret = "sk-real-openai-key-12345";
        let phantom = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";

        // Split secret across two chunks at various positions
        for split_pos in 1..secret.len() {
            let chunk1 = format!("prefix-{}", &secret[..split_pos]);
            let chunk2 = format!("{}-suffix", &secret[split_pos..]);

            let overlap_len = interceptor.max_secret_len().saturating_sub(1);
            let mut carry: Vec<u8> = Vec::new();
            let mut emitted = Vec::new();

            // Process chunk 1
            let mut combined = Vec::new();
            combined.extend_from_slice(&carry);
            combined.extend_from_slice(chunk1.as_bytes());
            let (scrubbed, _) = interceptor.scrub_response_bytes(&combined);
            if scrubbed.len() > overlap_len {
                let emit_end = scrubbed.len() - overlap_len;
                emitted.extend_from_slice(&scrubbed[..emit_end]);
                carry = scrubbed[emit_end..].to_vec();
            } else {
                carry = scrubbed;
            }

            // Process chunk 2
            let mut combined = Vec::new();
            combined.extend_from_slice(&carry);
            combined.extend_from_slice(chunk2.as_bytes());
            let (scrubbed, _) = interceptor.scrub_response_bytes(&combined);
            if scrubbed.len() > overlap_len {
                let emit_end = scrubbed.len() - overlap_len;
                emitted.extend_from_slice(&scrubbed[..emit_end]);
                carry = scrubbed[emit_end..].to_vec();
            } else {
                carry = scrubbed;
            }

            // Flush carry
            if !carry.is_empty() {
                let (scrubbed, _) = interceptor.scrub_response_bytes(&carry);
                emitted.extend_from_slice(&scrubbed);
            }

            let result = String::from_utf8(emitted).unwrap();
            assert!(
                !result.contains(secret),
                "Secret leaked at split_pos={split_pos}: {result}"
            );
            assert!(
                result.contains(phantom),
                "Phantom token missing at split_pos={split_pos}: {result}"
            );
        }
    }
}
