use std::collections::HashMap;
use zeroize::Zeroize;

use lazy_static::lazy_static;
use regex::Regex;

use phantom_core::audit::{LeakEvent, LeakLocation, LeakSeverity};

/// A secret-bearing string whose owned allocation is erased before release.
/// Deliberately does not implement `Debug` or `Display`.
#[derive(Clone)]
struct SecretValue {
    value: String,
}

impl SecretValue {
    fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    fn as_str(&self) -> &str {
        &self.value
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

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
    vault_values: Vec<(SecretValue, String)>,
}

impl ResponseLeakAnalyzer {
    /// Build an analyzer from the same `token→secret` mapping used by [`Interceptor`].
    /// `named_mappings` maps secret_key_name → real_secret_value.
    pub fn new(named_mappings: &HashMap<String, String>) -> Self {
        // Invert: value → name
        let vault_values = named_mappings
            .iter()
            .map(|(name, value)| (SecretValue::new(value.clone()), name.clone()))
            .collect();
        Self { vault_values }
    }

    /// Build from a token→secret mapping (same shape as Interceptor::new).
    /// The "name" reported in leak events will be the phantom token string since
    /// the named mapping isn't available in this form. Prefer [`new`] with named
    /// mappings for human-readable key names.
    pub fn from_token_map(token_to_secret: &HashMap<String, String>) -> Self {
        Self::from_token_secret_pairs(
            token_to_secret
                .iter()
                .map(|(token, secret)| (token.as_str(), secret.as_str())),
        )
    }

    pub(crate) fn from_token_secret_pairs<'a>(
        pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        // Here keys are phantom tokens — invert to secret→token while ensuring
        // the one required owned analyzer copy is zeroized on drop.
        let vault_values = pairs
            .into_iter()
            .map(|(token, secret)| (SecretValue::new(secret), token.to_string()))
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

    /// Return the name of an exact managed value represented by `candidate`.
    ///
    /// Streaming response scrubbing uses this byte-oriented view so it can
    /// protect non-UTF-8 responses without copying secret values into a second
    /// long-lived matcher.
    pub(crate) fn managed_exact_name(&self, candidate: &[u8]) -> Option<&str> {
        self.vault_values.iter().find_map(|(value, name)| {
            (value.as_str().as_bytes() == candidate).then_some(name.as_str())
        })
    }

    /// Whether `candidate` is a strict prefix of any managed value.
    pub(crate) fn is_managed_prefix(&self, candidate: &[u8]) -> bool {
        !candidate.is_empty()
            && self.vault_values.iter().any(|(value, _)| {
                let value = value.as_str().as_bytes();
                value.len() > candidate.len() && value.starts_with(candidate)
            })
    }

    /// Return the longest managed value that is a prefix of `candidate`.
    pub(crate) fn managed_prefix_match(&self, candidate: &[u8]) -> Option<(usize, &str)> {
        self.vault_values
            .iter()
            .filter_map(|(value, name)| {
                let value = value.as_str().as_bytes();
                (!value.is_empty() && candidate.starts_with(value))
                    .then_some((value.len(), name.as_str()))
            })
            .max_by_key(|(len, _)| *len)
    }

    pub(crate) fn max_managed_value_len(&self) -> usize {
        self.vault_values
            .iter()
            .map(|(value, _)| value.as_str().len())
            .max()
            .unwrap_or(0)
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Core scanner: vault-value match (HIGH) then format-pattern match (MEDIUM).
    fn scan_str(&self, input: &str, location: LeakLocation) -> (String, Vec<LeakEvent>) {
        let mut result = input.to_string();
        let mut events: Vec<LeakEvent> = Vec::new();
        let now = now_unix();

        // 1. Vault-value match (highest priority — confirmed live credential).
        for (secret_val, secret_name) in &self.vault_values {
            let secret_val = secret_val.as_str();
            if secret_val.is_empty() {
                continue;
            }
            let count = result.matches(secret_val).count();
            if count > 0 {
                // Determine a sensible pattern label from the value prefix.
                let pattern = format_pattern_label(secret_val);
                let next = result.replace(secret_val, &format!("[REDACTED:{}]", pattern));
                result.zeroize();
                result = next;
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
                self.vault_values
                    .iter()
                    .any(|(secret, _)| secret.as_str() == m.as_str())
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
                result.zeroize();
                result = scrubbed;
                // Avoid duplicate events if vault-match already fired for this pattern.
                let already_reported = events.iter().any(|e| e.pattern == *label);
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
    fn scan_bytes_vault_only(
        &self,
        input: &[u8],
        location: LeakLocation,
    ) -> (Vec<u8>, Vec<LeakEvent>) {
        let mut result = input.to_vec();
        let mut events = Vec::new();
        let now = now_unix();

        for (secret_val, secret_name) in &self.vault_values {
            let secret_val = secret_val.as_str();
            if secret_val.is_empty() {
                continue;
            }
            let needle = secret_val.as_bytes();
            let count = count_occurrences(&result, needle);
            if count > 0 {
                let pattern = format_pattern_label(secret_val);
                let replacement = format!("[REDACTED:{}]", pattern);
                let next = replace_bytes(&result, needle, replacement.as_bytes());
                result.zeroize();
                result = next;
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

/// Return a value-independent label for an exact vault-secret match.
///
/// Never derive response text, logs, or audit metadata from the secret itself:
/// even a prefix (or an entire short/non-ASCII value) crosses the value-blind
/// boundary that redaction is meant to enforce.
fn format_pattern_label(_value: &str) -> String {
    "vault-secret".to_string()
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

/// The interceptor injects configured route-owned secrets into fixed auth
/// headers and scrubs real secrets from API responses to prevent leakage.
/// Client-controlled phantom-token substitution is disabled in this release.
#[derive(Clone)]
pub struct Interceptor {
    /// phantom_token_string -> real_secret_value (for outgoing requests)
    token_map: HashMap<String, SecretValue>,
    /// Legacy phantom-token ownership metadata retained for compatibility.
    /// No client token resolves on a proxy route.
    token_secret_keys: HashMap<String, String>,
    /// env var / secret name -> real_secret_value (for configured header injection)
    named_secrets: HashMap<String, SecretValue>,
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
        let token_secret_keys = mappings
            .iter()
            .filter_map(|(token, value)| {
                let mut matches = named_mappings
                    .iter()
                    .filter(|(_, named_value)| *named_value == value)
                    .map(|(name, _)| name.clone());
                let name = matches.next()?;
                matches.next().is_none().then_some((token.clone(), name))
            })
            .collect();
        Self::new_scoped_inner(mappings, token_secret_keys, named_mappings)
    }

    /// Create an interceptor with explicit token ownership. This avoids
    /// inferring ownership from equal secret values and is the production
    /// constructor used by CLI sessions.
    pub fn new_scoped(
        mappings: HashMap<String, (String, String)>,
        named_mappings: HashMap<String, String>,
    ) -> Self {
        let token_secret_keys = mappings
            .iter()
            .map(|(token, (name, _))| (token.clone(), name.clone()))
            .collect();
        let values = mappings
            .into_iter()
            .map(|(token, (_, value))| (token, value))
            .collect();
        Self::new_scoped_inner(values, token_secret_keys, named_mappings)
    }

    fn new_scoped_inner(
        mappings: HashMap<String, String>,
        token_secret_keys: HashMap<String, String>,
        named_mappings: HashMap<String, String>,
    ) -> Self {
        let token_map = mappings
            .into_iter()
            .map(|(token, secret)| (token, SecretValue::new(secret)))
            .collect();
        let named_secrets = named_mappings
            .into_iter()
            .map(|(name, secret)| (name, SecretValue::new(secret)))
            .collect();
        Self {
            token_map,
            token_secret_keys,
            named_secrets,
        }
    }

    /// Compatibility API: client-controlled strings are never substituted.
    pub fn replace_in_str(&self, input: &str) -> (String, bool) {
        (input.to_string(), false)
    }

    /// Compatibility API: client-controlled bytes are never substituted.
    pub fn replace_in_bytes(&self, input: &[u8]) -> (Vec<u8>, bool) {
        (input.to_vec(), false)
    }

    /// Compatibility API: route ownership does not authorize substitution.
    pub fn replace_in_str_for_secret(&self, input: &str, _secret_key: &str) -> (String, bool) {
        (input.to_string(), false)
    }

    /// Byte-buffer equivalent of [`Self::replace_in_str_for_secret`].
    pub fn replace_in_bytes_for_secret(&self, input: &[u8], _secret_key: &str) -> (Vec<u8>, bool) {
        (input.to_vec(), false)
    }

    /// Compatibility API: phantom tokens cannot select an auth secret.
    pub fn format_header_value(&self, _format: &str, _phantom_token: &str) -> Option<String> {
        None
    }

    /// Format a header value using a configured secret name.
    pub fn format_header_for_secret_key(&self, format: &str, secret_key: &str) -> Option<String> {
        self.named_secrets
            .get(secret_key)
            .map(|secret| format.replace("{secret}", &secret.value))
    }

    /// Compatibility API: phantom tokens never resolve to real values.
    pub fn resolve(&self, _phantom_token: &str) -> Option<&str> {
        None
    }

    /// Compatibility API: client token inspection never authorizes resolution.
    pub fn contains_phantom_token(&self, _value: &str) -> bool {
        false
    }

    pub fn contains_phantom_token_for_secret(&self, _value: &str, _secret_key: &str) -> bool {
        let _ = &self.token_secret_keys;
        false
    }

    /// Number of token mappings.
    pub fn len(&self) -> usize {
        self.token_map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.token_map.is_empty()
    }

    /// Maximum length of any real secret in the zeroizing token map.
    /// Used to size the overlap window for streaming response scrubbing.
    pub fn max_secret_len(&self) -> usize {
        self.token_map
            .values()
            .map(|secret| secret.as_str().len())
            .max()
            .unwrap_or(0)
    }

    /// Scrub real secrets from a response string, replacing them with phantom tokens.
    /// Prevents API responses from leaking real credentials back to AI agents.
    pub fn scrub_response_str(&self, input: &str) -> (String, bool) {
        let pairs: Vec<(&str, &str)> = self
            .token_map
            .iter()
            .map(|(token, secret)| (secret.as_str(), token.as_str()))
            .collect();
        find_replace_str(input, &pairs)
    }

    /// Scrub real secrets from response bytes.
    pub fn scrub_response_bytes(&self, input: &[u8]) -> (Vec<u8>, bool) {
        let pairs: Vec<(&str, &str)> = self
            .token_map
            .iter()
            .map(|(token, secret)| (secret.as_str(), token.as_str()))
            .collect();
        find_replace_bytes_via_str(input, &pairs)
    }

    /// Build a [`crate::response_scrubber::ResponseScrubber`] from this interceptor's
    /// token→secret mapping.  The scrubber adds audit logging and stderr warnings on
    /// top of the basic byte-replacement already performed by [`scrub_response_bytes`].
    pub fn to_response_scrubber(&self) -> crate::response_scrubber::ResponseScrubber {
        crate::response_scrubber::ResponseScrubber::from_token_secret_pairs(
            self.token_map
                .iter()
                .map(|(token, secret)| (token.as_str(), secret.as_str())),
        )
    }
}

/// Find-and-replace multiple string patterns. Returns the result and whether any replacement was made.
fn find_replace_str(input: &str, pairs: &[(&str, &str)]) -> (String, bool) {
    let mut result = input.to_string();
    let mut replaced = false;
    for &(needle, replacement) in pairs {
        if result.contains(needle) {
            let next = result.replace(needle, replacement);
            result.zeroize();
            result = next;
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
        result.zeroize();
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
    fn test_client_header_value_is_inert() {
        let interceptor = test_interceptor();
        let (result, replaced) = interceptor.replace_in_str(
            "Bearer phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222",
        );
        assert!(!replaced);
        assert!(result.contains("phm_"));
        assert!(!result.contains("sk-real-openai-key-12345"));
    }

    #[test]
    fn test_client_body_is_inert() {
        let interceptor = test_interceptor();
        let body = r#"{"api_key": "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"}"#;
        let (result, replaced) = interceptor.replace_in_bytes(body.as_bytes());
        assert!(!replaced);
        let result_str = String::from_utf8(result).unwrap();
        assert!(!result_str.contains("sk-real-openai-key-12345"));
        assert!(result_str.contains("phm_"));
    }

    #[test]
    fn test_no_replacement_needed() {
        let interceptor = test_interceptor();
        let (result, replaced) = interceptor.replace_in_str("Bearer sk-real-key");
        assert!(!replaced);
        assert_eq!(result, "Bearer sk-real-key");
    }

    #[test]
    fn test_compatibility_token_checks_are_inert() {
        let interceptor = test_interceptor();
        assert!(!interceptor.contains_phantom_token(
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
            None
        );
        assert_eq!(interceptor.resolve("phm_nonexistent"), None);
    }

    #[test]
    fn all_client_token_compatibility_apis_fail_closed() {
        let token = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
        let secret = "sk-real-openai-key-12345";
        let mut scoped = HashMap::new();
        scoped.insert(
            token.to_string(),
            ("OPENAI_API_KEY".to_string(), secret.to_string()),
        );
        let mut named = HashMap::new();
        named.insert("OPENAI_API_KEY".to_string(), secret.to_string());
        let interceptor = Interceptor::new_scoped(scoped, named);

        let (text, text_changed) = interceptor.replace_in_str_for_secret(token, "OPENAI_API_KEY");
        let (bytes, bytes_changed) =
            interceptor.replace_in_bytes_for_secret(token.as_bytes(), "OPENAI_API_KEY");
        assert_eq!(text, token);
        assert!(!text_changed);
        assert_eq!(bytes, token.as_bytes());
        assert!(!bytes_changed);
        assert!(!interceptor.contains_phantom_token_for_secret(token, "OPENAI_API_KEY"));
        assert_eq!(
            interceptor.format_header_value("Bearer {secret}", token),
            None
        );
        assert_eq!(
            interceptor.format_header_for_secret_key("Bearer {secret}", "OPENAI_API_KEY"),
            Some(format!("Bearer {secret}"))
        );
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
    fn test_multiple_client_tokens_remain_inert() {
        let interceptor = test_interceptor();
        let body = "key1=phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222&key2=phm_1111222233334444555566667777888899990000aaaabbbbccccddddeeee0000";
        let (result, replaced) = interceptor.replace_in_str(body);
        assert!(!replaced);
        assert!(!result.contains("sk-real-openai-key-12345"));
        assert!(!result.contains("sk-ant-real-anthropic-key"));
        assert_eq!(result.matches("phm_").count(), 2);
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
