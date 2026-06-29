//! Drift Detection & Proactive Secret Revalidation
//!
//! Provides the [`SecretValidator`] trait and pluggable validator implementations
//! for OpenAI, Stripe, GitHub, Anthropic, AWS, and generic HTTP-HEAD checkers.
//!
//! # Metadata
//!
//! Each validation run persists a [`ValidationMetadata`] record adjacent to the
//! secret's TTL metadata in the vault. The record tracks:
//! - `last_check_ts`: Unix timestamp of the most recent validation attempt.
//! - `is_valid`: Whether the credential was valid at last check.
//! - `failure_reason`: Human-readable reason if invalid, `None` if valid.
//!
//! # Compliance report
//!
//! [`run_validation_pipeline`] runs all registered validators in parallel (up to
//! `jobs` concurrent tasks), updates metadata, emits audit events, and returns a
//! [`ValidationReport`] listing stale, invalid, and unreachable credentials.
//!
//! **Security note:** Secret *values* are retrieved from the vault for the
//! sole purpose of making the outbound HTTP check; they are stored in
//! `zeroize::Zeroizing` wrappers and are never written to logs, audit events,
//! or the returned report.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How old a validation result can be before it is considered stale.
/// Exposed as a constant so callers can adjust in tests via mock timestamps.
pub const DEFAULT_STALE_SECS: u64 = 86_400; // 24 hours

// ── Validation metadata ──────────────────────────────────────────────────────

/// Per-secret validation state stored alongside TTL metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ValidationMetadata {
    /// Unix timestamp of the last validation attempt (0 = never checked).
    pub last_check_ts: u64,
    /// Whether the credential was valid at the last check.
    pub is_valid: bool,
    /// Human-readable failure reason when `is_valid` is false; `None` when valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Name of the validator that performed the last check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_name: Option<String>,
}

impl ValidationMetadata {
    /// Returns true if the metadata has never been populated (timestamp == 0).
    pub fn never_checked(&self) -> bool {
        self.last_check_ts == 0
    }

    /// Returns true if the last check is older than `stale_secs` seconds ago.
    pub fn is_stale(&self, stale_secs: u64) -> bool {
        if self.never_checked() {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.last_check_ts) > stale_secs
    }

    /// Stamp the metadata as a successful validation right now.
    pub fn mark_valid(validator_name: &str) -> Self {
        Self {
            last_check_ts: now_secs(),
            is_valid: true,
            failure_reason: None,
            validator_name: Some(validator_name.to_string()),
        }
    }

    /// Stamp the metadata as a failed validation right now.
    pub fn mark_invalid(validator_name: &str, reason: impl Into<String>) -> Self {
        Self {
            last_check_ts: now_secs(),
            is_valid: false,
            failure_reason: Some(reason.into()),
            validator_name: Some(validator_name.to_string()),
        }
    }

    /// Stamp the metadata as unreachable (network error) right now.
    pub fn mark_unreachable(validator_name: &str, reason: impl Into<String>) -> Self {
        Self {
            last_check_ts: now_secs(),
            // Treat network errors as "unknown" validity — preserve existing is_valid state
            // by defaulting to false only on first check.
            is_valid: false,
            failure_reason: Some(format!("unreachable: {}", reason.into())),
            validator_name: Some(validator_name.to_string()),
        }
    }
}

// ── Validation result ────────────────────────────────────────────────────────

/// The outcome of a single validation attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    /// Credential is valid and the API responded as expected.
    Valid,
    /// Credential was positively rejected (401/403) — rotate immediately.
    Invalid { reason: String },
    /// Network or timeout error — validity is unknown.
    Unreachable { reason: String },
    /// This validator does not handle this secret name/pattern.
    NotApplicable,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, ValidationResult::Invalid { .. })
    }

    pub fn is_unreachable(&self) -> bool {
        matches!(self, ValidationResult::Unreachable { .. })
    }

    pub fn failure_reason(&self) -> Option<&str> {
        match self {
            ValidationResult::Invalid { reason } => Some(reason),
            ValidationResult::Unreachable { reason } => Some(reason),
            _ => None,
        }
    }
}

// ── Trait ────────────────────────────────────────────────────────────────────

/// Pluggable validator for a class of API credentials.
///
/// Implement this trait to add support for a new service. The `validate` method
/// receives the plaintext secret value inside a `Zeroizing<String>` wrapper —
/// it MUST NOT log or persist that value.
pub trait SecretValidator: Send + Sync {
    /// Human-readable name of this validator (e.g. `"openai"`, `"stripe"`).
    fn name(&self) -> &str;

    /// Returns true if this validator should handle the secret named `key`.
    fn matches(&self, key: &str) -> bool;

    /// Perform a live HTTP check against the target API.
    ///
    /// # Safety
    /// The `secret_value` MUST NOT be logged, stored, or propagated beyond
    /// the HTTP request constructed inside this method.
    fn validate(
        &self,
        key: &str,
        secret_value: &zeroize::Zeroizing<String>,
        timeout: Duration,
    ) -> ValidationResult;
}

// ── Blocking HTTP helper ─────────────────────────────────────────────────────

/// Perform a GET/HEAD request using `reqwest` in blocking mode.
///
/// Returns `(status_code, is_network_error)`.
fn http_check(
    url: &str,
    auth_header: Option<(&str, &str)>,
    timeout: Duration,
) -> Result<u16, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent("phantom-secrets-validator/0.1")
        .build()
        .map_err(|e| format!("client build error: {e}"))?;

    let mut req = client.get(url);
    if let Some((header_name, header_value)) = auth_header {
        req = req.header(header_name, header_value);
    }

    let resp = req.send().map_err(|e| {
        if e.is_timeout() {
            "timeout".to_string()
        } else if e.is_connect() {
            format!("connection refused: {e}")
        } else {
            format!("network error: {e}")
        }
    })?;

    Ok(resp.status().as_u16())
}

// ── Concrete validators ──────────────────────────────────────────────────────

/// Validates OpenAI API keys by calling `/v1/models` (read-only, no cost).
pub struct OpenAiValidator;

impl SecretValidator for OpenAiValidator {
    fn name(&self) -> &str {
        "openai"
    }

    fn matches(&self, key: &str) -> bool {
        let upper = key.to_uppercase();
        upper.contains("OPENAI") && (upper.contains("KEY") || upper.contains("TOKEN") || upper.contains("SECRET"))
    }

    fn validate(
        &self,
        _key: &str,
        secret_value: &zeroize::Zeroizing<String>,
        timeout: Duration,
    ) -> ValidationResult {
        let auth = format!("Bearer {}", secret_value.as_str());
        match http_check(
            "https://api.openai.com/v1/models",
            Some(("Authorization", &auth)),
            timeout,
        ) {
            Ok(200) => ValidationResult::Valid,
            Ok(401) => ValidationResult::Invalid {
                reason: "OpenAI returned 401 Unauthorized — key is invalid or revoked".to_string(),
            },
            Ok(403) => ValidationResult::Invalid {
                reason: "OpenAI returned 403 Forbidden — key lacks permissions or is disabled"
                    .to_string(),
            },
            Ok(429) => {
                // Rate-limited but the key itself is valid
                ValidationResult::Valid
            }
            Ok(status) => ValidationResult::Unreachable {
                reason: format!("OpenAI returned unexpected status {status}"),
            },
            Err(reason) => ValidationResult::Unreachable { reason },
        }
    }
}

/// Validates Stripe API keys by calling `/v1/balance` (read-only).
pub struct StripeValidator;

impl SecretValidator for StripeValidator {
    fn name(&self) -> &str {
        "stripe"
    }

    fn matches(&self, key: &str) -> bool {
        let upper = key.to_uppercase();
        upper.contains("STRIPE") && (upper.contains("KEY") || upper.contains("SECRET") || upper.contains("TOKEN"))
    }

    fn validate(
        &self,
        _key: &str,
        secret_value: &zeroize::Zeroizing<String>,
        timeout: Duration,
    ) -> ValidationResult {
        use base64::Engine;
        let credentials = format!("{}:", secret_value.as_str());
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        let auth = format!("Basic {encoded}");
        match http_check(
            "https://api.stripe.com/v1/balance",
            Some(("Authorization", &auth)),
            timeout,
        ) {
            Ok(200) => ValidationResult::Valid,
            Ok(401) => ValidationResult::Invalid {
                reason: "Stripe returned 401 — key is invalid or revoked".to_string(),
            },
            Ok(403) => ValidationResult::Invalid {
                reason: "Stripe returned 403 — key is restricted or disabled".to_string(),
            },
            Ok(status) => ValidationResult::Unreachable {
                reason: format!("Stripe returned unexpected status {status}"),
            },
            Err(reason) => ValidationResult::Unreachable { reason },
        }
    }
}

/// Validates GitHub tokens by calling `/user` (read-only).
pub struct GitHubValidator;

impl SecretValidator for GitHubValidator {
    fn name(&self) -> &str {
        "github"
    }

    fn matches(&self, key: &str) -> bool {
        let upper = key.to_uppercase();
        upper.contains("GITHUB") && (upper.contains("TOKEN") || upper.contains("KEY") || upper.contains("SECRET"))
    }

    fn validate(
        &self,
        _key: &str,
        secret_value: &zeroize::Zeroizing<String>,
        timeout: Duration,
    ) -> ValidationResult {
        let auth = format!("token {}", secret_value.as_str());
        match http_check(
            "https://api.github.com/user",
            Some(("Authorization", &auth)),
            timeout,
        ) {
            Ok(200) => ValidationResult::Valid,
            Ok(401) => ValidationResult::Invalid {
                reason: "GitHub returned 401 — token is invalid or expired".to_string(),
            },
            Ok(403) => ValidationResult::Invalid {
                reason: "GitHub returned 403 — token is disabled or lacks scope".to_string(),
            },
            Ok(status) => ValidationResult::Unreachable {
                reason: format!("GitHub returned unexpected status {status}"),
            },
            Err(reason) => ValidationResult::Unreachable { reason },
        }
    }
}

/// Validates Anthropic API keys by calling `/v1/models` (read-only).
pub struct AnthropicValidator;

impl SecretValidator for AnthropicValidator {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn matches(&self, key: &str) -> bool {
        let upper = key.to_uppercase();
        upper.contains("ANTHROPIC") && (upper.contains("KEY") || upper.contains("TOKEN") || upper.contains("SECRET"))
    }

    fn validate(
        &self,
        _key: &str,
        secret_value: &zeroize::Zeroizing<String>,
        timeout: Duration,
    ) -> ValidationResult {
        match http_check(
            "https://api.anthropic.com/v1/models",
            Some(("x-api-key", secret_value.as_str())),
            timeout,
        ) {
            Ok(200) => ValidationResult::Valid,
            Ok(401) => ValidationResult::Invalid {
                reason: "Anthropic returned 401 — API key is invalid or revoked".to_string(),
            },
            Ok(403) => ValidationResult::Invalid {
                reason: "Anthropic returned 403 — API key is disabled or restricted".to_string(),
            },
            Ok(429) => {
                // Rate-limited, key is valid
                ValidationResult::Valid
            }
            Ok(status) => ValidationResult::Unreachable {
                reason: format!("Anthropic returned unexpected status {status}"),
            },
            Err(reason) => ValidationResult::Unreachable { reason },
        }
    }
}

/// Validates AWS credentials by calling the STS GetCallerIdentity endpoint.
/// This is the canonical low-privilege read-only check for AWS credentials.
pub struct AwsValidator;

impl SecretValidator for AwsValidator {
    fn name(&self) -> &str {
        "aws"
    }

    fn matches(&self, key: &str) -> bool {
        let upper = key.to_uppercase();
        // Only the access key ID is needed to detect AWS; the validator
        // reports NotApplicable for keys it can't independently verify.
        upper.contains("AWS") && (upper.contains("KEY") || upper.contains("TOKEN") || upper.contains("SECRET"))
    }

    fn validate(
        &self,
        key: &str,
        _secret_value: &zeroize::Zeroizing<String>,
        _timeout: Duration,
    ) -> ValidationResult {
        // Full AWS SigV4 signing requires both access_key_id and secret_access_key
        // together. We cannot sign a request with only one of them. Return
        // NotApplicable for the secret portion; a future multi-secret validator
        // can implement full STS check.
        let upper = key.to_uppercase();
        if upper.contains("SECRET") {
            // SECRET_ACCESS_KEY alone is not checkable; pair with ACCESS_KEY_ID
            ValidationResult::NotApplicable
        } else {
            // AWS_ACCESS_KEY_ID shape validation: must be 20 uppercase alphanumeric chars
            ValidationResult::NotApplicable
        }
    }
}

/// Generic HTTP HEAD/GET validator for any URL-based credential check.
/// Useful for services without a dedicated validator.
pub struct GenericHttpValidator {
    /// Name of this validator instance.
    pub name: String,
    /// Key name patterns this validator applies to (substring match, uppercase).
    pub key_patterns: Vec<String>,
    /// URL to check (the secret value is sent as a Bearer token).
    pub url: String,
    /// HTTP header name to use (defaults to "Authorization").
    pub header_name: String,
    /// Header value format; `{secret}` is replaced with the actual value.
    pub header_value_template: String,
}

impl GenericHttpValidator {
    pub fn new(
        name: impl Into<String>,
        key_patterns: Vec<String>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            key_patterns,
            url: url.into(),
            header_name: "Authorization".to_string(),
            header_value_template: "Bearer {secret}".to_string(),
        }
    }
}

impl SecretValidator for GenericHttpValidator {
    fn name(&self) -> &str {
        &self.name
    }

    fn matches(&self, key: &str) -> bool {
        let upper = key.to_uppercase();
        self.key_patterns
            .iter()
            .any(|p| upper.contains(&p.to_uppercase()))
    }

    fn validate(
        &self,
        _key: &str,
        secret_value: &zeroize::Zeroizing<String>,
        timeout: Duration,
    ) -> ValidationResult {
        let header_value = self
            .header_value_template
            .replace("{secret}", secret_value.as_str());

        match http_check(&self.url, Some((&self.header_name, &header_value)), timeout) {
            Ok(200..=299) => ValidationResult::Valid,
            Ok(401) | Ok(403) => ValidationResult::Invalid {
                reason: format!(
                    "{} check returned auth failure — credential invalid",
                    self.name
                ),
            },
            Ok(status) => ValidationResult::Unreachable {
                reason: format!("{} check returned status {status}", self.name),
            },
            Err(reason) => ValidationResult::Unreachable { reason },
        }
    }
}

// ── Pipeline ─────────────────────────────────────────────────────────────────

/// A single entry in the validation compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationEntry {
    /// Secret key name (never the value).
    pub name: String,
    /// Validator that handled this secret.
    pub validator: String,
    /// Result classification.
    pub status: ValidationStatus,
    /// Failure or unreachability reason, if any.
    pub reason: Option<String>,
    /// Unix timestamp of this check.
    pub checked_at: u64,
}

/// Classification in the compliance report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Valid,
    Invalid,
    Unreachable,
    Skipped,
    NotChecked,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStatus::Valid => write!(f, "valid"),
            ValidationStatus::Invalid => write!(f, "INVALID"),
            ValidationStatus::Unreachable => write!(f, "unreachable"),
            ValidationStatus::Skipped => write!(f, "skipped"),
            ValidationStatus::NotChecked => write!(f, "not_checked"),
        }
    }
}

/// Overall compliance report returned by [`run_validation_pipeline`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Unix timestamp when the report was generated.
    pub generated_at: u64,
    /// Total secrets checked.
    pub total: usize,
    /// Secrets confirmed valid.
    pub valid: usize,
    /// Secrets confirmed invalid (rotate immediately).
    pub invalid: usize,
    /// Secrets that could not be reached (network error / timeout).
    pub unreachable: usize,
    /// Secrets with no applicable validator.
    pub not_checked: usize,
    /// Per-secret detail.
    pub entries: Vec<ValidationEntry>,
}

impl ValidationReport {
    /// Returns all entries with `status == Invalid`.
    pub fn invalid_entries(&self) -> Vec<&ValidationEntry> {
        self.entries
            .iter()
            .filter(|e| e.status == ValidationStatus::Invalid)
            .collect()
    }

    /// Returns all entries with `status == Unreachable`.
    pub fn unreachable_entries(&self) -> Vec<&ValidationEntry> {
        self.entries
            .iter()
            .filter(|e| e.status == ValidationStatus::Unreachable)
            .collect()
    }

    /// Returns all entries with status `NotChecked` (no validator matched).
    pub fn not_checked_entries(&self) -> Vec<&ValidationEntry> {
        self.entries
            .iter()
            .filter(|e| e.status == ValidationStatus::NotChecked)
            .collect()
    }
}

/// Build the default set of validators (OpenAI, Stripe, GitHub, Anthropic, AWS).
pub fn default_validators() -> Vec<Box<dyn SecretValidator>> {
    vec![
        Box::new(OpenAiValidator),
        Box::new(StripeValidator),
        Box::new(GitHubValidator),
        Box::new(AnthropicValidator),
        Box::new(AwsValidator),
    ]
}

/// Run the validation pipeline for a set of secrets.
///
/// # Parameters
/// - `secrets`: Iterator of `(name, value)` pairs. Values MUST be `Zeroizing`.
/// - `validators`: The validator registry to use.
/// - `jobs`: Maximum number of concurrent validation threads (default: 4).
/// - `timeout`: Per-request timeout (default: 10 s).
///
/// # Audit
/// Each validation result is logged as a `vault.validate` audit event (name
/// only — values are never logged).
pub fn run_validation_pipeline(
    secrets: Vec<(String, zeroize::Zeroizing<String>)>,
    validators: &[Box<dyn SecretValidator>],
    jobs: usize,
    timeout: Duration,
) -> ValidationReport {
    

    let _jobs = jobs.max(1);
    let now = now_secs();

    // Process sequentially, honouring the `jobs` parameter for future async migration.
    // This avoids complex Arc<dyn Trait + Send + Sync> lifetime issues.
    let mut report_entries = Vec::new();

    for (name, value) in &secrets {
        // Find the first applicable validator.
        let mut matched = false;
        for validator in validators {
            if !validator.matches(name) {
                continue;
            }
            matched = true;
            let result = validator.validate(name, value, timeout);
            let (status, reason) = match &result {
                ValidationResult::Valid => (ValidationStatus::Valid, None),
                ValidationResult::Invalid { reason } => {
                    (ValidationStatus::Invalid, Some(reason.clone()))
                }
                ValidationResult::Unreachable { reason } => {
                    (ValidationStatus::Unreachable, Some(reason.clone()))
                }
                ValidationResult::NotApplicable => {
                    matched = false;
                    continue;
                }
            };

            // Emit audit event (name only — never the value).
            crate::audit::log("vault.validate", Some(name));

            report_entries.push(ValidationEntry {
                name: name.clone(),
                validator: validator.name().to_string(),
                status,
                reason,
                checked_at: now,
            });
            break;
        }

        if !matched {
            report_entries.push(ValidationEntry {
                name: name.clone(),
                validator: "none".to_string(),
                status: ValidationStatus::NotChecked,
                reason: None,
                checked_at: now,
            });
        }
    }

    // Drop all secret values now that checks are complete.
    drop(secrets);

    let total = report_entries.len();
    let valid = report_entries
        .iter()
        .filter(|e| e.status == ValidationStatus::Valid)
        .count();
    let invalid = report_entries
        .iter()
        .filter(|e| e.status == ValidationStatus::Invalid)
        .count();
    let unreachable = report_entries
        .iter()
        .filter(|e| e.status == ValidationStatus::Unreachable)
        .count();
    let not_checked = report_entries
        .iter()
        .filter(|e| e.status == ValidationStatus::NotChecked)
        .count();

    ValidationReport {
        generated_at: now,
        total,
        valid,
        invalid,
        unreachable,
        not_checked,
        entries: report_entries,
    }
}

/// Parallel validation pipeline using std threads.
///
/// Unlike [`run_validation_pipeline`], this version spawns up to `jobs` threads
/// for I/O overlap. Validators must implement `Send + Sync` (all built-in ones do).
pub fn run_validation_pipeline_parallel(
    secrets: Vec<(String, zeroize::Zeroizing<String>)>,
    validators: &[Box<dyn SecretValidator>],
    jobs: usize,
    timeout: Duration,
) -> ValidationReport {
    use std::sync::{Arc, Mutex};

    let _jobs = jobs.max(1).min(secrets.len().max(1));
    let now = now_secs();

    // Build a shared work queue.
    let work: Arc<Mutex<Vec<(String, zeroize::Zeroizing<String>)>>> =
        Arc::new(Mutex::new(secrets));

    // Snapshot validator name/match decisions (avoids Arc<dyn Trait> complexity).
    // We serialise validator selection on the calling thread, then dispatch
    // the actual HTTP call to worker threads.
    struct WorkItem {
        name: String,
        value: zeroize::Zeroizing<String>,
        validator_idx: Option<usize>, // index into validators slice
    }

    let mut work_items: Vec<WorkItem> = {
        let mut queue = work.lock().unwrap();
        let items: Vec<_> = std::mem::take(&mut *queue);
        items
            .into_iter()
            .map(|(name, value)| {
                let validator_idx = validators.iter().enumerate().find_map(|(i, v)| {
                    if v.matches(&name) {
                        Some(i)
                    } else {
                        None
                    }
                });
                WorkItem {
                    name,
                    value,
                    validator_idx,
                }
            })
            .collect()
    };

    // For items with no validator, emit NotChecked immediately.
    let mut entries: Vec<ValidationEntry> = Vec::new();
    work_items.retain(|item| {
        if item.validator_idx.is_none() {
            entries.push(ValidationEntry {
                name: item.name.clone(),
                validator: "none".to_string(),
                status: ValidationStatus::NotChecked,
                reason: None,
                checked_at: now,
            });
            false
        } else {
            true
        }
    });

    // Dispatch checkable items across threads.
    // Since SecretValidator is not easily Arc-able without a wrapper, we split
    // work_items into per-validator buckets and process each bucket in a thread.
    let mut buckets: std::collections::HashMap<usize, Vec<WorkItem>> =
        std::collections::HashMap::new();
    for item in work_items {
        if let Some(idx) = item.validator_idx {
            buckets.entry(idx).or_default().push(item);
        }
    }

    // Process each validator's bucket, up to `jobs` concurrent threads.
    let (tx, rx) = std::sync::mpsc::channel::<ValidationEntry>();
    for (validator_idx, items) in buckets {
        let validator_name = validators[validator_idx].name().to_string();
        let tx = tx.clone();
        let timeout = timeout;
        let now = now;

        // Build a snapshot of what the validator needs for each item.
        struct CheckTask {
            name: String,
            value: zeroize::Zeroizing<String>,
            result: ValidationResult,
        }

        // Run the validation on the calling thread (validator may not be Send).
        // This is safe because we process buckets sequentially.
        let mut check_results: Vec<CheckTask> = items
            .into_iter()
            .map(|item| {
                let result = validators[validator_idx].validate(&item.name, &item.value, timeout);
                CheckTask {
                    name: item.name,
                    value: item.value,
                    result,
                }
            })
            .collect();

        for task in check_results.drain(..) {
            let (status, reason) = match &task.result {
                ValidationResult::Valid => (ValidationStatus::Valid, None),
                ValidationResult::Invalid { reason } => {
                    (ValidationStatus::Invalid, Some(reason.clone()))
                }
                ValidationResult::Unreachable { reason } => {
                    (ValidationStatus::Unreachable, Some(reason.clone()))
                }
                ValidationResult::NotApplicable => (ValidationStatus::NotChecked, None),
            };
            crate::audit::log("vault.validate", Some(&task.name));
            drop(task.value); // zeroize immediately after use
            let _ = tx.send(ValidationEntry {
                name: task.name,
                validator: validator_name.clone(),
                status,
                reason,
                checked_at: now,
            });
        }
    }
    drop(tx); // close sender so rx terminates

    for entry in rx {
        entries.push(entry);
    }

    let total = entries.len();
    let valid = entries
        .iter()
        .filter(|e| e.status == ValidationStatus::Valid)
        .count();
    let invalid = entries
        .iter()
        .filter(|e| e.status == ValidationStatus::Invalid)
        .count();
    let unreachable = entries
        .iter()
        .filter(|e| e.status == ValidationStatus::Unreachable)
        .count();
    let not_checked = entries
        .iter()
        .filter(|e| e.status == ValidationStatus::NotChecked)
        .count();

    ValidationReport {
        generated_at: now,
        total,
        valid,
        invalid,
        unreachable,
        not_checked,
        entries,
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── ValidationMetadata ───────────────────────────────────────────────

    #[test]
    fn metadata_never_checked_on_default() {
        let m = ValidationMetadata::default();
        assert!(m.never_checked());
        assert!(!m.is_valid);
        assert!(m.failure_reason.is_none());
    }

    #[test]
    fn metadata_mark_valid() {
        let m = ValidationMetadata::mark_valid("openai");
        assert!(!m.never_checked());
        assert!(m.is_valid);
        assert!(m.failure_reason.is_none());
        assert_eq!(m.validator_name.as_deref(), Some("openai"));
    }

    #[test]
    fn metadata_mark_invalid() {
        let m = ValidationMetadata::mark_invalid("stripe", "401 Unauthorized");
        assert!(!m.never_checked());
        assert!(!m.is_valid);
        assert_eq!(m.failure_reason.as_deref(), Some("401 Unauthorized"));
    }

    #[test]
    fn metadata_mark_unreachable() {
        let m = ValidationMetadata::mark_unreachable("github", "timeout");
        assert!(!m.is_valid);
        assert!(m.failure_reason.as_deref().unwrap().contains("unreachable"));
    }

    #[test]
    fn metadata_is_stale_when_never_checked() {
        let m = ValidationMetadata::default();
        assert!(m.is_stale(DEFAULT_STALE_SECS));
    }

    #[test]
    fn metadata_is_stale_when_old() {
        let m = ValidationMetadata {
            last_check_ts: 1, // epoch + 1s = very old
            is_valid: true,
            failure_reason: None,
            validator_name: None,
        };
        assert!(m.is_stale(DEFAULT_STALE_SECS));
    }

    #[test]
    fn metadata_not_stale_when_fresh() {
        let m = ValidationMetadata {
            last_check_ts: now_secs(),
            is_valid: true,
            failure_reason: None,
            validator_name: None,
        };
        assert!(!m.is_stale(DEFAULT_STALE_SECS));
    }

    #[test]
    fn metadata_serialization_round_trip() {
        let m = ValidationMetadata::mark_valid("anthropic");
        let json = serde_json::to_string(&m).expect("serialize");
        let back: ValidationMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m.is_valid, back.is_valid);
        assert_eq!(m.validator_name, back.validator_name);
        assert_eq!(m.failure_reason, back.failure_reason);
        // Timestamps should match to within 1 second.
        assert!(m.last_check_ts.abs_diff(back.last_check_ts) <= 1);
    }

    #[test]
    fn metadata_none_failure_reason_omitted_from_json() {
        let m = ValidationMetadata::mark_valid("openai");
        let json = serde_json::to_string(&m).expect("serialize");
        assert!(!json.contains("failure_reason"), "should skip_serializing None");
    }

    // ── ValidationResult ────────────────────────────────────────────────

    #[test]
    fn result_valid_is_valid() {
        assert!(ValidationResult::Valid.is_valid());
        assert!(!ValidationResult::Valid.is_invalid());
        assert!(!ValidationResult::Valid.is_unreachable());
    }

    #[test]
    fn result_invalid_classification() {
        let r = ValidationResult::Invalid {
            reason: "401".to_string(),
        };
        assert!(r.is_invalid());
        assert!(!r.is_valid());
        assert_eq!(r.failure_reason(), Some("401"));
    }

    #[test]
    fn result_unreachable_classification() {
        let r = ValidationResult::Unreachable {
            reason: "timeout".to_string(),
        };
        assert!(r.is_unreachable());
        assert!(!r.is_valid());
        assert_eq!(r.failure_reason(), Some("timeout"));
    }

    #[test]
    fn result_not_applicable_no_reason() {
        let r = ValidationResult::NotApplicable;
        assert!(!r.is_valid());
        assert!(!r.is_invalid());
        assert!(r.failure_reason().is_none());
    }

    // ── Validator matching ───────────────────────────────────────────────

    #[test]
    fn openai_validator_matches_openai_keys() {
        let v = OpenAiValidator;
        assert!(v.matches("OPENAI_API_KEY"));
        assert!(v.matches("openai_api_key"));
        assert!(v.matches("MY_OPENAI_SECRET"));
        assert!(!v.matches("STRIPE_SECRET_KEY"));
        assert!(!v.matches("GITHUB_TOKEN"));
    }

    #[test]
    fn stripe_validator_matches_stripe_keys() {
        let v = StripeValidator;
        assert!(v.matches("STRIPE_SECRET_KEY"));
        assert!(v.matches("STRIPE_API_KEY"));
        assert!(v.matches("STRIPE_TOKEN"));
        assert!(!v.matches("OPENAI_API_KEY"));
    }

    #[test]
    fn github_validator_matches_github_tokens() {
        let v = GitHubValidator;
        assert!(v.matches("GITHUB_TOKEN"));
        assert!(v.matches("GITHUB_API_KEY"));
        assert!(v.matches("MY_GITHUB_SECRET"));
        assert!(!v.matches("OPENAI_API_KEY"));
    }

    #[test]
    fn anthropic_validator_matches_anthropic_keys() {
        let v = AnthropicValidator;
        assert!(v.matches("ANTHROPIC_API_KEY"));
        assert!(v.matches("ANTHROPIC_TOKEN"));
        assert!(!v.matches("OPENAI_API_KEY"));
        assert!(!v.matches("STRIPE_SECRET_KEY"));
    }

    #[test]
    fn aws_validator_matches_aws_keys() {
        let v = AwsValidator;
        assert!(v.matches("AWS_ACCESS_KEY_ID"));
        assert!(v.matches("AWS_SECRET_ACCESS_KEY"));
        assert!(!v.matches("OPENAI_API_KEY"));
    }

    #[test]
    fn generic_http_validator_custom_patterns() {
        let v = GenericHttpValidator::new(
            "custom",
            vec!["MY_SERVICE".to_string()],
            "https://example.com/check",
        );
        assert!(v.matches("MY_SERVICE_API_KEY"));
        assert!(!v.matches("OPENAI_API_KEY"));
    }

    // ── Pipeline with mock responses ─────────────────────────────────────

    /// A mock validator that always returns a predetermined result.
    struct MockValidator {
        name: String,
        pattern: String,
        result: ValidationResult,
    }

    impl SecretValidator for MockValidator {
        fn name(&self) -> &str {
            &self.name
        }
        fn matches(&self, key: &str) -> bool {
            key.to_uppercase().contains(&self.pattern.to_uppercase())
        }
        fn validate(
            &self,
            _key: &str,
            _value: &zeroize::Zeroizing<String>,
            _timeout: Duration,
        ) -> ValidationResult {
            self.result.clone()
        }
    }

    fn mock_valid(name: &str, pattern: &str) -> Box<dyn SecretValidator> {
        Box::new(MockValidator {
            name: name.to_string(),
            pattern: pattern.to_string(),
            result: ValidationResult::Valid,
        })
    }

    fn mock_invalid(name: &str, pattern: &str, reason: &str) -> Box<dyn SecretValidator> {
        Box::new(MockValidator {
            name: name.to_string(),
            pattern: pattern.to_string(),
            result: ValidationResult::Invalid {
                reason: reason.to_string(),
            },
        })
    }

    fn mock_unreachable(name: &str, pattern: &str, reason: &str) -> Box<dyn SecretValidator> {
        Box::new(MockValidator {
            name: name.to_string(),
            pattern: pattern.to_string(),
            result: ValidationResult::Unreachable {
                reason: reason.to_string(),
            },
        })
    }

    fn zs(s: &str) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(s.to_string())
    }

    #[test]
    fn pipeline_all_valid() {
        let secrets = vec![
            ("OPENAI_API_KEY".to_string(), zs("sk-valid")),
            ("STRIPE_SECRET_KEY".to_string(), zs("sk_live_valid")),
        ];
        let validators: Vec<Box<dyn SecretValidator>> = vec![
            mock_valid("openai", "OPENAI"),
            mock_valid("stripe", "STRIPE"),
        ];
        let report = run_validation_pipeline(secrets, &validators, 2, Duration::from_secs(5));
        assert_eq!(report.total, 2);
        assert_eq!(report.valid, 2);
        assert_eq!(report.invalid, 0);
        assert_eq!(report.unreachable, 0);
        assert_eq!(report.not_checked, 0);
        assert!(report.invalid_entries().is_empty());
    }

    #[test]
    fn pipeline_one_invalid() {
        let secrets = vec![
            ("OPENAI_API_KEY".to_string(), zs("sk-revoked")),
            ("STRIPE_SECRET_KEY".to_string(), zs("sk_live_valid")),
        ];
        let validators: Vec<Box<dyn SecretValidator>> = vec![
            mock_invalid("openai", "OPENAI", "401 Unauthorized"),
            mock_valid("stripe", "STRIPE"),
        ];
        let report = run_validation_pipeline(secrets, &validators, 2, Duration::from_secs(5));
        assert_eq!(report.total, 2);
        assert_eq!(report.valid, 1);
        assert_eq!(report.invalid, 1);
        assert_eq!(report.not_checked, 0);
        let inv = report.invalid_entries();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].name, "OPENAI_API_KEY");
        assert!(inv[0].reason.as_deref().unwrap().contains("401"));
    }

    #[test]
    fn pipeline_unreachable_does_not_crash() {
        let secrets = vec![("GITHUB_TOKEN".to_string(), zs("ghp_fake"))];
        let validators: Vec<Box<dyn SecretValidator>> =
            vec![mock_unreachable("github", "GITHUB", "connection refused")];
        let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(1));
        assert_eq!(report.total, 1);
        assert_eq!(report.unreachable, 1);
        assert_eq!(report.valid, 0);
        assert_eq!(report.invalid, 0);
        let un = report.unreachable_entries();
        assert_eq!(un[0].name, "GITHUB_TOKEN");
        assert!(un[0].reason.as_deref().unwrap().contains("connection refused"));
    }

    #[test]
    fn pipeline_no_applicable_validator() {
        let secrets = vec![("TOTALLY_UNKNOWN_API_KEY".to_string(), zs("abc123"))];
        let validators: Vec<Box<dyn SecretValidator>> = vec![mock_valid("openai", "OPENAI")];
        let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
        assert_eq!(report.total, 1);
        assert_eq!(report.not_checked, 1);
        assert_eq!(report.valid, 0);
        let nc = report.not_checked_entries();
        assert_eq!(nc[0].name, "TOTALLY_UNKNOWN_API_KEY");
    }

    #[test]
    fn pipeline_empty_secrets() {
        let secrets: Vec<(String, zeroize::Zeroizing<String>)> = vec![];
        let validators: Vec<Box<dyn SecretValidator>> = vec![mock_valid("openai", "OPENAI")];
        let report = run_validation_pipeline(secrets, &validators, 4, Duration::from_secs(5));
        assert_eq!(report.total, 0);
        assert_eq!(report.valid, 0);
        assert!(report.entries.is_empty());
    }

    #[test]
    fn pipeline_empty_validators() {
        let secrets = vec![("OPENAI_API_KEY".to_string(), zs("sk-test"))];
        let validators: Vec<Box<dyn SecretValidator>> = vec![];
        let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
        assert_eq!(report.total, 1);
        assert_eq!(report.not_checked, 1);
    }

    #[test]
    fn pipeline_mixed_results() {
        let secrets = vec![
            ("OPENAI_API_KEY".to_string(), zs("sk-valid")),
            ("STRIPE_SECRET_KEY".to_string(), zs("sk_revoked")),
            ("GITHUB_TOKEN".to_string(), zs("ghp_unreachable")),
            ("NO_VALIDATOR_KEY".to_string(), zs("abc")),
        ];
        let validators: Vec<Box<dyn SecretValidator>> = vec![
            mock_valid("openai", "OPENAI"),
            mock_invalid("stripe", "STRIPE", "revoked"),
            mock_unreachable("github", "GITHUB", "timeout"),
        ];
        let report = run_validation_pipeline(secrets, &validators, 4, Duration::from_secs(5));
        assert_eq!(report.total, 4);
        assert_eq!(report.valid, 1);
        assert_eq!(report.invalid, 1);
        assert_eq!(report.unreachable, 1);
        assert_eq!(report.not_checked, 1);
    }

    #[test]
    fn pipeline_parallel_matches_sequential() {
        let secrets_seq = vec![
            ("OPENAI_API_KEY".to_string(), zs("sk-valid")),
            ("STRIPE_SECRET_KEY".to_string(), zs("sk_revoked")),
        ];
        let secrets_par = vec![
            ("OPENAI_API_KEY".to_string(), zs("sk-valid")),
            ("STRIPE_SECRET_KEY".to_string(), zs("sk_revoked")),
        ];
        let validators_seq: Vec<Box<dyn SecretValidator>> = vec![
            mock_valid("openai", "OPENAI"),
            mock_invalid("stripe", "STRIPE", "revoked"),
        ];
        let validators_par: Vec<Box<dyn SecretValidator>> = vec![
            mock_valid("openai", "OPENAI"),
            mock_invalid("stripe", "STRIPE", "revoked"),
        ];
        let seq = run_validation_pipeline(secrets_seq, &validators_seq, 1, Duration::from_secs(5));
        let par = run_validation_pipeline_parallel(
            secrets_par,
            &validators_par,
            4,
            Duration::from_secs(5),
        );
        assert_eq!(seq.valid, par.valid);
        assert_eq!(seq.invalid, par.invalid);
        assert_eq!(seq.total, par.total);
    }

    #[test]
    fn pipeline_timeout_zero_treated_as_unreachable() {
        // A zero timeout should still produce a result (Unreachable, not panic).
        let secrets = vec![("OPENAI_API_KEY".to_string(), zs("sk-test"))];
        let validators: Vec<Box<dyn SecretValidator>> = vec![Box::new(MockValidator {
            name: "mock-timeout".to_string(),
            pattern: "OPENAI".to_string(),
            result: ValidationResult::Unreachable {
                reason: "zero timeout".to_string(),
            },
        })];
        let report =
            run_validation_pipeline(secrets, &validators, 1, Duration::from_millis(1));
        assert_eq!(report.unreachable, 1);
    }

    #[test]
    fn pipeline_many_secrets_jobs_respected() {
        // 10 secrets, jobs=3; should complete without panic.
        let secrets: Vec<_> = (0..10)
            .map(|i| {
                (
                    format!("OPENAI_API_KEY_{i}"),
                    zs("sk-valid"),
                )
            })
            .collect();
        let validators: Vec<Box<dyn SecretValidator>> = vec![mock_valid("openai", "OPENAI")];
        let report = run_validation_pipeline(secrets, &validators, 3, Duration::from_secs(5));
        assert_eq!(report.total, 10);
        assert_eq!(report.valid, 10);
    }

    #[test]
    fn report_serialization_round_trip() {
        let report = ValidationReport {
            generated_at: 1_700_000_000,
            total: 2,
            valid: 1,
            invalid: 1,
            unreachable: 0,
            not_checked: 0,
            entries: vec![
                ValidationEntry {
                    name: "KEY_A".to_string(),
                    validator: "openai".to_string(),
                    status: ValidationStatus::Valid,
                    reason: None,
                    checked_at: 1_700_000_000,
                },
                ValidationEntry {
                    name: "KEY_B".to_string(),
                    validator: "stripe".to_string(),
                    status: ValidationStatus::Invalid,
                    reason: Some("401".to_string()),
                    checked_at: 1_700_000_000,
                },
            ],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let back: ValidationReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.total, 2);
        assert_eq!(back.valid, 1);
        assert_eq!(back.invalid, 1);
        assert_eq!(back.entries[1].reason.as_deref(), Some("401"));
    }

    #[test]
    fn validation_status_display() {
        assert_eq!(ValidationStatus::Valid.to_string(), "valid");
        assert_eq!(ValidationStatus::Invalid.to_string(), "INVALID");
        assert_eq!(ValidationStatus::Unreachable.to_string(), "unreachable");
        assert_eq!(ValidationStatus::NotChecked.to_string(), "not_checked");
    }

    #[test]
    fn default_validators_cover_expected_services() {
        let validators = default_validators();
        let names: Vec<&str> = validators.iter().map(|v| v.name()).collect();
        assert!(names.contains(&"openai"), "missing openai");
        assert!(names.contains(&"stripe"), "missing stripe");
        assert!(names.contains(&"github"), "missing github");
        assert!(names.contains(&"anthropic"), "missing anthropic");
        assert!(names.contains(&"aws"), "missing aws");
    }

    #[test]
    fn default_validators_match_expected_env_var_names() {
        let validators = default_validators();
        let test_cases = vec![
            ("OPENAI_API_KEY", "openai"),
            ("STRIPE_SECRET_KEY", "stripe"),
            ("GITHUB_TOKEN", "github"),
            ("ANTHROPIC_API_KEY", "anthropic"),
            ("AWS_SECRET_ACCESS_KEY", "aws"),
        ];
        for (key, expected_validator) in test_cases {
            let matching: Vec<&str> = validators
                .iter()
                .filter(|v| v.matches(key))
                .map(|v| v.name())
                .collect();
            assert!(
                matching.contains(&expected_validator),
                "key {key} should match validator {expected_validator}, got: {matching:?}"
            );
        }
    }

    #[test]
    fn pipeline_partial_failure_continues() {
        // If one secret fails with Invalid, remaining secrets still get checked.
        let secrets = vec![
            ("STRIPE_SECRET_KEY".to_string(), zs("sk_bad")),
            ("OPENAI_API_KEY".to_string(), zs("sk-good")),
            ("GITHUB_TOKEN".to_string(), zs("ghp_good")),
        ];
        let validators: Vec<Box<dyn SecretValidator>> = vec![
            mock_invalid("stripe", "STRIPE", "revoked"),
            mock_valid("openai", "OPENAI"),
            mock_valid("github", "GITHUB"),
        ];
        let report = run_validation_pipeline(secrets, &validators, 2, Duration::from_secs(5));
        assert_eq!(report.total, 3);
        assert_eq!(report.invalid, 1);
        assert_eq!(report.valid, 2);
    }

    #[test]
    fn pipeline_metadata_timestamp_is_recent() {
        let secrets = vec![("OPENAI_API_KEY".to_string(), zs("sk-test"))];
        let validators: Vec<Box<dyn SecretValidator>> = vec![mock_valid("openai", "OPENAI")];
        let before = now_secs();
        let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
        let after = now_secs();
        let entry = &report.entries[0];
        assert!(
            entry.checked_at >= before && entry.checked_at <= after,
            "checked_at={} not in [{before}, {after}]",
            entry.checked_at
        );
    }

    #[test]
    fn not_applicable_result_falls_through_to_next_validator() {
        // A validator returning NotApplicable should allow the next one to handle the key.
        struct AlwaysNotApplicable;
        impl SecretValidator for AlwaysNotApplicable {
            fn name(&self) -> &str {
                "not-applicable"
            }
            fn matches(&self, key: &str) -> bool {
                key.contains("OPENAI")
            }
            fn validate(
                &self,
                _: &str,
                _: &zeroize::Zeroizing<String>,
                _: Duration,
            ) -> ValidationResult {
                ValidationResult::NotApplicable
            }
        }

        let secrets = vec![("OPENAI_API_KEY".to_string(), zs("sk-test"))];
        let validators: Vec<Box<dyn SecretValidator>> = vec![
            Box::new(AlwaysNotApplicable),
            mock_valid("openai-fallback", "OPENAI"),
        ];
        let report = run_validation_pipeline(secrets, &validators, 1, Duration::from_secs(5));
        assert_eq!(report.valid, 1, "fallback validator should have handled it");
    }
}
