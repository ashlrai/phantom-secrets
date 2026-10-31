use std::collections::HashMap;
use zeroize::Zeroize;

use phantom_core::audit::{LeakEvent, LeakLocation, LeakSeverity};
use phantom_core::redact::response::FORMAT_SPECS;

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
// ResponseLeakAnalyzer
// ──────────────────────────────────────────────────────────────────────────────

/// Analyzes upstream API responses for real secrets that escaped scrubbing.
///
/// Two detection modes are applied together:
/// 1. **Vault-value match**: compares response content against every real secret
///    in the active injection map. Any hit is HIGH severity and names the key.
/// 2. **Format-pattern match**: scans the shared response-credential byte grammars.
///    Hits that are NOT in the vault injection map are MEDIUM severity (the
///    response may contain credentials that aren't under Phantom management).
///
/// Detected leaks are replaced with `[REDACTED:<pattern>]` in the returned
/// bytes, and [`LeakEvent`]s are returned for the caller to emit / log.
#[derive(Clone)]
pub struct ResponseLeakAnalyzer {
    /// real_secret_value -> secret_key_name (from vault injection map).
    vault_values: Vec<(SecretValue, String)>,
    /// Prefilter for partial-run matching: one bit per hashed
    /// [`PARTIAL_MIN_RUN`]-byte window of every token-like managed value.
    /// Holds hash bits only, never window plaintext; every bitset hit is
    /// verified against the value itself before anything is redacted.
    partial_filter: Option<Box<[u64]>>,
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
        Self::with_partial_filter(vault_values)
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
        Self::with_partial_filter(vault_values)
    }

    fn with_partial_filter(vault_values: Vec<(SecretValue, String)>) -> Self {
        let mut bits = vec![0u64; PARTIAL_FILTER_WORDS];
        let mut any = false;
        for (value, _) in &vault_values {
            let value = value.as_str().as_bytes();
            for start in partial_window_starts(value) {
                let bit = partial_bit(window_hash(&value[start..start + PARTIAL_MIN_RUN]));
                bits[bit / 64] |= 1 << (bit % 64);
                any = true;
            }
        }
        Self {
            vault_values,
            partial_filter: any.then(|| bits.into_boxed_slice()),
        }
    }

    /// Whether any managed value is eligible for partial-run redaction.
    pub(crate) fn has_partial_matching(&self) -> bool {
        self.partial_filter.is_some()
    }

    /// Name reported for the managed value at `index`.
    pub(crate) fn vault_name(&self, index: usize) -> &str {
        self.vault_values[index].1.as_str()
    }

    /// Maximal runs in `input` made of [`PARTIAL_MIN_RUN`]-byte windows that
    /// also occur in a token-like managed value, outside its public prefix.
    /// Returns `(start, end, value_index)` sorted, non-overlapping.
    pub(crate) fn partial_runs(&self, input: &[u8]) -> Vec<(usize, usize, usize)> {
        let Some(filter) = self.partial_filter.as_deref() else {
            return Vec::new();
        };
        if input.len() < PARTIAL_MIN_RUN {
            return Vec::new();
        }
        let mut runs: Vec<(usize, usize, usize)> = Vec::new();
        let mut hash = window_hash(&input[..PARTIAL_MIN_RUN]);
        let mut start = 0;
        loop {
            let bit = partial_bit(hash);
            if filter[bit / 64] & (1 << (bit % 64)) != 0 {
                let window = &input[start..start + PARTIAL_MIN_RUN];
                if let Some(index) = self.verify_partial_window(window) {
                    let end = start + PARTIAL_MIN_RUN;
                    match runs.last_mut() {
                        Some(last) if start <= last.1 => last.1 = last.1.max(end),
                        _ => runs.push((start, end, index)),
                    }
                }
            }
            let next = start + PARTIAL_MIN_RUN;
            if next >= input.len() {
                break;
            }
            hash = roll_hash(hash, input[start], input[next]);
            start += 1;
        }
        runs
    }

    /// Where a stream may stop emitting: the start of the shortest trailing
    /// suffix (under [`PARTIAL_MIN_RUN`] bytes) that is a prefix of some
    /// eligible window, or `input.len()` when none is. Only such a suffix can
    /// still become a run once more bytes arrive; every earlier unfinished
    /// window already disagrees with every value, so holding nothing else
    /// keeps streams prompt.
    pub(crate) fn partial_hold_start(&self, input: &[u8]) -> usize {
        if self.partial_filter.is_none() {
            return input.len();
        }
        let from = input.len().saturating_sub(PARTIAL_MIN_RUN - 1);
        (from..input.len())
            .find(|&j| {
                let suffix = &input[j..];
                self.vault_values.iter().any(|(value, _)| {
                    let value = value.as_str().as_bytes();
                    partial_window_starts(value)
                        .any(|start| value[start..start + PARTIAL_MIN_RUN].starts_with(suffix))
                })
            })
            .unwrap_or(input.len())
    }

    fn verify_partial_window(&self, window: &[u8]) -> Option<usize> {
        self.vault_values.iter().position(|(value, _)| {
            let value = value.as_str().as_bytes();
            partial_window_starts(value)
                .any(|start| &value[start..start + PARTIAL_MIN_RUN] == window)
        })
    }

    /// Replace every partial run in `input` with a vault-secret marker, one
    /// event per managed value. For `str` callers, runs are widened to char
    /// boundaries so the result stays valid UTF-8.
    fn redact_partial_runs(
        &self,
        input: &[u8],
        char_boundary: Option<&str>,
        location: &LeakLocation,
        events: &mut Vec<LeakEvent>,
    ) -> Option<Vec<u8>> {
        let runs = self.partial_runs(input);
        if runs.is_empty() {
            return None;
        }
        let marker = format!("[REDACTED:{}]", format_pattern_label(""));
        let mut output = Vec::with_capacity(input.len());
        let mut cursor = 0;
        let now = now_unix();
        for (mut start, mut end, index) in runs {
            if let Some(text) = char_boundary {
                while start > 0 && !text.is_char_boundary(start) {
                    start -= 1;
                }
                while end < text.len() && !text.is_char_boundary(end) {
                    end += 1;
                }
            }
            start = start.max(cursor);
            if end <= start {
                continue;
            }
            output.extend_from_slice(&input[cursor..start]);
            output.extend_from_slice(marker.as_bytes());
            cursor = end;
            let name = self.vault_name(index).to_string();
            if let Some(event) = events.iter_mut().find(|e| {
                e.pattern == "vault-secret" && e.secret_name.as_deref() == Some(name.as_str())
            }) {
                event.match_count += 1;
            } else {
                events.push(LeakEvent {
                    ts: now,
                    location: location.clone(),
                    severity: LeakSeverity::High,
                    secret_name: Some(name),
                    pattern: format_pattern_label(""),
                    match_count: 1,
                });
            }
        }
        output.extend_from_slice(&input[cursor..]);
        Some(output)
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

    /// Borrow managed bytes for streaming matching without another plaintext owner.
    pub(crate) fn managed_values(&self) -> impl Iterator<Item = (&[u8], &str)> {
        self.vault_values
            .iter()
            .map(|(value, name)| (value.as_str().as_bytes(), name.as_str()))
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

        // 1b. Partial runs of a managed value (a vendor echoing part of the
        //     key). Exact matches above are already replaced.
        if let Some(next) = self.redact_partial_runs(
            result.as_bytes(),
            Some(result.as_str()),
            &location,
            &mut events,
        ) {
            // Runs are widened to char boundaries, so this cannot fail; keep
            // the original on the impossible path rather than panic.
            if let Ok(next) = String::from_utf8(next) {
                result.zeroize();
                result = next;
            }
        }

        // 2. Format-pattern match (catches secrets not yet in vault injection map).
        for spec in FORMAT_SPECS {
            let label = spec.label;
            // Count remaining matches (after vault replacements above).
            let matches = spec.match_ranges(result.as_bytes());
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
                    .any(|(secret, _)| secret.as_str() == &result[m.clone()])
            });
            let severity = if is_vault_confirmed {
                LeakSeverity::High
            } else {
                LeakSeverity::Medium
            };
            // Replace with [REDACTED:<label>].
            let replacement = format!("[REDACTED:{}]", label);
            let mut scrubbed = String::with_capacity(result.len());
            let mut cursor = 0;
            for range in matches {
                // The shared grammar matches ASCII bytes only, so these ranges
                // always lie on UTF-8 boundaries in this string input.
                scrubbed.push_str(&result[cursor..range.start]);
                scrubbed.push_str(&replacement);
                cursor = range.end;
            }
            scrubbed.push_str(&result[cursor..]);
            if scrubbed != result {
                result.zeroize();
                result = scrubbed;
                // Avoid duplicate events if vault-match already fired for this pattern.
                let already_reported = events.iter().any(|e| e.pattern == label);
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

        if let Some(next) = self.redact_partial_runs(&result, None, &location, &mut events) {
            result.zeroize();
            result = next;
        }

        (result, events)
    }
}

/// Minimum run of consecutive managed-value bytes that is redacted when it
/// appears in a response without the rest of the value.
pub(crate) const PARTIAL_MIN_RUN: usize = 12;
/// Values shorter than this are matched exactly only.
const PARTIAL_MIN_VALUE_LEN: usize = 16;
/// Public prefixes (`sk-ant-api03-`, `sk_live_`) are searched for in the first
/// this-many bytes.
const PUBLIC_PREFIX_SCAN: usize = 16;
const PARTIAL_FILTER_WORDS: usize = 1024; // 65,536 bits, 8 KiB
const WINDOW_HASH_BASE: u64 = 0x0000_0100_0000_01b3;

/// Token-like values (API keys, JWTs) qualify for partial matching. Values
/// with spaces, `:` or `@` (passphrases, connection strings) do not, because
/// a 12-byte run of them can be ordinary text such as `localhost:5432`.
fn is_token_like(value: &[u8]) -> bool {
    value.len() >= PARTIAL_MIN_VALUE_LEN
        && value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+/=~".contains(b))
}

/// Length of a value's public prefix: through the last `-` or `_` in its
/// first [`PUBLIC_PREFIX_SCAN`] bytes. Masked displays show this prefix.
fn public_prefix_len(value: &[u8]) -> usize {
    let head = &value[..value.len().min(PUBLIC_PREFIX_SCAN)];
    head.iter()
        .rposition(|b| *b == b'-' || *b == b'_')
        .map(|i| i + 1)
        .unwrap_or(0)
}

/// Window starts eligible for partial matching: token-like values only, and
/// never a window that lies entirely inside the public prefix, so a masked
/// form such as `sk-ant-api03-...wxyz` is not redacted.
fn partial_window_starts(value: &[u8]) -> impl Iterator<Item = usize> {
    let eligible = is_token_like(value) && value.len() >= PARTIAL_MIN_RUN;
    let prefix = public_prefix_len(value);
    let first = prefix.saturating_sub(PARTIAL_MIN_RUN - 1);
    let last = if eligible {
        value.len() - PARTIAL_MIN_RUN + 1
    } else {
        0
    };
    first.min(last)..last
}

fn window_hash(window: &[u8]) -> u64 {
    window.iter().fold(0u64, |h, &b| {
        h.wrapping_mul(WINDOW_HASH_BASE)
            .wrapping_add(u64::from(b) + 1)
    })
}

/// `WINDOW_HASH_BASE ^ (PARTIAL_MIN_RUN - 1)`, the weight of a window's
/// first byte.
const WINDOW_HASH_TOP: u64 = {
    let mut p = 1u64;
    let mut i = 0;
    while i < PARTIAL_MIN_RUN - 1 {
        p = p.wrapping_mul(WINDOW_HASH_BASE);
        i += 1;
    }
    p
};

fn roll_hash(hash: u64, outgoing: u8, incoming: u8) -> u64 {
    hash.wrapping_sub((u64::from(outgoing) + 1).wrapping_mul(WINDOW_HASH_TOP))
        .wrapping_mul(WINDOW_HASH_BASE)
        .wrapping_add(u64::from(incoming) + 1)
}

fn partial_bit(hash: u64) -> usize {
    (hash.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 48) as usize
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

    /// Build an HTTP Basic `Authorization` value whose password is the vault
    /// value for `secret_key`. `username` must be a non-secret identifier the
    /// caller has already validated (it must not contain `:`). Intermediate
    /// buffers holding the secret are zeroized on drop.
    pub fn format_basic_auth_for_secret_key(
        &self,
        username: &str,
        secret_key: &str,
    ) -> Option<zeroize::Zeroizing<String>> {
        use base64::Engine as _;
        if username.contains(':') {
            return None;
        }
        let secret = self.named_secrets.get(secret_key)?;
        let mut pair = zeroize::Zeroizing::new(String::with_capacity(
            username.len() + 1 + secret.value.len(),
        ));
        pair.push_str(username);
        pair.push(':');
        pair.push_str(secret.as_str());
        // Encode straight into a zeroizing buffer of the exact length.
        // `encode_slice` writes into the caller's buffer with no internal
        // staging copy, unlike `encode_string`'s chunked stack buffer.
        let encoded_len = base64::encoded_len(pair.len(), true)?;
        let mut encoded = zeroize::Zeroizing::new(vec![0u8; encoded_len]);
        let written = base64::engine::general_purpose::STANDARD
            .encode_slice(pair.as_bytes(), encoded.as_mut_slice())
            .ok()?;
        let encoded = encoded.get(..written)?;
        let mut value =
            zeroize::Zeroizing::new(String::with_capacity("Basic ".len() + encoded.len()));
        value.push_str("Basic ");
        value.push_str(std::str::from_utf8(encoded).ok()?);
        Some(value)
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
        self.to_response_scrubber_with_injected(None)
    }

    /// Like [`Self::to_response_scrubber`], plus one request-specific value
    /// the proxy derived from a vault value and sent upstream, as
    /// `(secret_key_name, derived_value)`. Used for the encoded
    /// `base64(username:secret)` of a Basic route: an upstream that echoes
    /// it would otherwise hand the client a trivially decodable credential.
    pub fn to_response_scrubber_with_injected(
        &self,
        injected: Option<(&str, &str)>,
    ) -> crate::response_scrubber::ResponseScrubber {
        crate::response_scrubber::ResponseScrubber::from_token_secret_pairs(
            self.token_map
                .iter()
                .map(|(token, secret)| (token.as_str(), secret.as_str()))
                .chain(injected.filter(|(_, value)| !value.is_empty())),
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
    fn basic_auth_value_uses_vault_password_and_rejects_bad_usernames() {
        use base64::Engine as _;
        use rand::RngCore;
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        let secret_value = hex::encode(random);
        let secret = secret_value.as_str();
        let interceptor = Interceptor::new_scoped(
            HashMap::new(),
            HashMap::from([("BASIC_SECRET".to_string(), secret.to_string())]),
        );
        let value = interceptor
            .format_basic_auth_for_secret_key("acct", "BASIC_SECRET")
            .unwrap();
        let expected = base64::engine::general_purpose::STANDARD.encode(format!("acct:{secret}"));
        assert_eq!(value.as_str(), format!("Basic {expected}"));
        // Every padding length round-trips and no reallocation is needed.
        for password_len in 0..6 {
            let password = secret_value[..password_len].to_string();
            let interceptor = Interceptor::new_scoped(
                HashMap::new(),
                HashMap::from([("BASIC_SECRET".to_string(), password.clone())]),
            );
            let value = interceptor
                .format_basic_auth_for_secret_key("u", "BASIC_SECRET")
                .unwrap();
            let expected =
                base64::engine::general_purpose::STANDARD.encode(format!("u:{password}"));
            assert_eq!(value.as_str(), format!("Basic {expected}"));
            assert_eq!(value.capacity(), value.len());
        }
        assert!(interceptor
            .format_basic_auth_for_secret_key("a:b", "BASIC_SECRET")
            .is_none());
        assert!(interceptor
            .format_basic_auth_for_secret_key("acct", "MISSING")
            .is_none());
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
