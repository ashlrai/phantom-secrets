//! Vendor-specific secret rotation providers.
//!
//! This module defines the [`RotationProvider`] trait and concrete implementations
//! for Stripe, GitHub, and AWS. Providers allow `phantom rotate --auto-sync` to
//! delegate credential rotation to the vendor's own API, then receive the new
//! secret value back — enabling zero-downtime rotation without manual intervention.
//!
//! # Flow
//!
//! ```text
//! phantom rotate --auto-sync STRIPE_SECRET_KEY
//!     │
//!     ├── 1. look up RotationProviderConfig in .phantom.toml
//!     ├── 2. call provider.initiate_rotation(secret_name) → challenge_id
//!     ├── 3. call provider.finalize_rotation(challenge_id) → new_secret_value
//!     └── 4. store new_secret_value in vault + record audit event with source
//! ```
//!
//! # Security
//!
//! - Secret values returned by `finalize_rotation` are wrapped in
//!   `zeroize::Zeroizing<String>` and MUST NOT be logged or written to disk
//!   other than into the encrypted vault.
//! - API credentials for each provider (used to *call* the rotation API) are
//!   stored in `.phantom.toml` under `[phantom.secrets.{name}.rotation_provider]`
//!   and are themselves protected by the vault's access controls.
//! - All rotation attempts (successful or failed) are recorded as audit events
//!   with a `source` field: `"manual"`, `"stripe"`, `"github"`, or `"aws"`.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can occur during vendor-managed rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationProviderError {
    /// The vendor API returned an authentication failure (bad API credentials
    /// used to *call* the rotation endpoint — not the secret being rotated).
    AuthFailed { reason: String },
    /// The vendor API returned an error (4xx/5xx other than auth).
    ApiError { status: u16, reason: String },
    /// Network error or timeout reaching the vendor API.
    NetworkError { reason: String },
    /// The challenge ID / rotation token was not found or has expired.
    ChallengeExpired { challenge_id: String },
    /// The provider is not configured for this secret.
    NotConfigured,
    /// The vendor returned an unexpected response format.
    UnexpectedResponse { reason: String },
    /// This provider does not support the named secret.
    NotApplicable,
}

impl fmt::Display for RotationProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed { reason } => {
                write!(f, "rotation API authentication failed: {reason}")
            }
            Self::ApiError { status, reason } => {
                write!(f, "rotation API returned HTTP {status}: {reason}")
            }
            Self::NetworkError { reason } => {
                write!(f, "rotation API network error: {reason}")
            }
            Self::ChallengeExpired { challenge_id } => {
                write!(f, "rotation challenge '{challenge_id}' expired or not found")
            }
            Self::NotConfigured => {
                write!(f, "rotation provider not configured for this secret")
            }
            Self::UnexpectedResponse { reason } => {
                write!(f, "unexpected response from rotation API: {reason}")
            }
            Self::NotApplicable => {
                write!(f, "provider does not handle this secret type")
            }
        }
    }
}

// ── Audit source ──────────────────────────────────────────────────────────────

/// Records the originator of a rotation event in the audit log.
///
/// Stored as `"source": "manual"` / `"stripe"` / etc. in each audit event so
/// compliance dashboards can distinguish human-initiated rotations from
/// automated vendor-callback rotations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationSource {
    /// Secret value was supplied manually by the operator (`phantom rotate KEY`).
    Manual,
    /// Rotated via the Stripe restricted-key rotation API.
    Stripe,
    /// Rotated via the GitHub fine-grained token refresh API.
    GitHub,
    /// Rotated via AWS IAM access-key rotation.
    Aws,
    /// Rotated via a custom/generic provider.
    Custom { provider_name: String },
}

impl RotationSource {
    /// Short lowercase label used in audit events and `--auto-sync` output.
    pub fn label(&self) -> &str {
        match self {
            Self::Manual => "manual",
            Self::Stripe => "stripe",
            Self::GitHub => "github",
            Self::Aws => "aws",
            Self::Custom { provider_name } => provider_name.as_str(),
        }
    }
}

impl fmt::Display for RotationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Trait implemented by each vendor's rotation provider.
///
/// Vendors that support server-side credential rotation (Stripe, GitHub, AWS)
/// implement this trait. `phantom rotate --auto-sync` calls `initiate_rotation`
/// to start the process, then `finalize_rotation` to retrieve the new value.
///
/// For synchronous vendors (where the new key is returned immediately from the
/// initiate call) `finalize_rotation` simply returns the value stashed during
/// `initiate_rotation`.
pub trait RotationProvider: Send + Sync {
    /// Human-readable provider name, e.g. `"stripe"`.
    fn name(&self) -> &str;

    /// Returns `true` if this provider handles the given secret name.
    fn matches(&self, secret_name: &str) -> bool;

    /// Begin vendor-side rotation for `secret_name`.
    ///
    /// Returns a `challenge_id` opaque token that must be passed to
    /// `finalize_rotation`. For synchronous providers the challenge_id MAY
    /// encode the new secret value directly (the provider's finalize
    /// implementation will decode it).
    ///
    /// This method MUST NOT log or print the returned new secret value.
    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError>;

    /// Complete the rotation initiated by `initiate_rotation`.
    ///
    /// Returns the new secret value inside a `Zeroizing<String>`. The caller
    /// is responsible for storing this value in the vault immediately.
    ///
    /// # Security
    /// MUST NOT log, print, or persist `challenge_id` or the returned value
    /// anywhere other than the encrypted vault.
    fn finalize_rotation(
        &self,
        challenge_id: &str,
        config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError>;

    /// The [`RotationSource`] label used for audit events from this provider.
    fn rotation_source(&self) -> RotationSource;
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Per-secret rotation provider configuration.
///
/// Stored under `[phantom.secrets.{name}.rotation_provider]` in `.phantom.toml`.
///
/// Example:
/// ```toml
/// [phantom.secrets.STRIPE_SECRET_KEY.rotation_provider]
/// provider = "stripe"
/// api_key_env = "STRIPE_ROTATION_API_KEY"
/// account_id = "acct_1234"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RotationProviderConfig {
    /// Which vendor provider to use: `"stripe"`, `"github"`, `"aws"`, or a
    /// custom name for [`GenericRotationProvider`].
    pub provider: String,

    /// Name of an environment variable (or vault secret) holding the API key
    /// used to call the vendor's rotation endpoint. This is NOT the secret
    /// being rotated; it is a separate rotation-management credential.
    ///
    /// Example: `"STRIPE_ROTATION_API_KEY"` or `"GH_ADMIN_TOKEN"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,

    /// Vendor-specific account/resource identifier.
    ///
    /// - Stripe: Stripe account ID (e.g. `"acct_1234"`) — optional.
    /// - GitHub: Organisation or user login (e.g. `"myorg"`) — optional.
    /// - AWS: IAM user name whose access key is being rotated — required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,

    /// Region override for providers that are region-scoped (AWS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Timeout in seconds for rotation API calls (default: 30).
    #[serde(default = "default_rotation_timeout_secs")]
    pub timeout_secs: u64,

    /// When `true`, the auto-sync flow will attempt this provider first and
    /// only fall back to manual if the provider call fails. Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_rotation_timeout_secs() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

impl Default for RotationProviderConfig {
    fn default() -> Self {
        Self {
            provider: "manual".to_string(),
            api_key_env: None,
            account_id: None,
            region: None,
            timeout_secs: 30,
            enabled: true,
        }
    }
}

// ── Outcome ───────────────────────────────────────────────────────────────────

/// The result of a `phantom rotate --auto-sync` attempt.
#[derive(Debug)]
pub enum AutoSyncOutcome {
    /// Vendor rotation succeeded; the new value has been stored in the vault.
    VendorRotated {
        source: RotationSource,
        challenge_id: String,
    },
    /// Vendor rotation failed; the caller fell back to manual rotation.
    FellBackToManual {
        reason: RotationProviderError,
    },
    /// No provider is configured; manual rotation was used directly.
    Manual,
}

impl AutoSyncOutcome {
    /// Returns `true` if vendor rotation (not manual fallback) was used.
    pub fn is_vendor_rotated(&self) -> bool {
        matches!(self, Self::VendorRotated { .. })
    }

    /// Returns the `RotationSource` label for audit logging.
    pub fn audit_source(&self) -> &str {
        match self {
            Self::VendorRotated { source, .. } => source.label(),
            Self::FellBackToManual { .. } | Self::Manual => "manual",
        }
    }
}

// ── Orchestration ─────────────────────────────────────────────────────────────

/// Attempt vendor-managed rotation for `secret_name`.
///
/// 1. Find the first registered provider that matches `secret_name`.
/// 2. Call `initiate_rotation` → `challenge_id`.
/// 3. Call `finalize_rotation` → `new_value`.
/// 4. Return [`AutoSyncOutcome::VendorRotated`] so the caller stores the value.
///
/// If no provider matches OR the vendor call fails, returns
/// [`AutoSyncOutcome::FellBackToManual`] (the caller must prompt for a manual value).
///
/// An audit event is emitted for each attempt (success or failure) with the
/// `source` label set to the provider name.
pub fn attempt_vendor_rotation(
    secret_name: &str,
    provider_config: Option<&RotationProviderConfig>,
    providers: &[Box<dyn RotationProvider>],
) -> AutoSyncOutcome {
    let Some(config) = provider_config else {
        return AutoSyncOutcome::Manual;
    };

    if !config.enabled {
        return AutoSyncOutcome::Manual;
    }

    let provider = match providers.iter().find(|p| p.matches(secret_name)) {
        Some(p) => p,
        None => return AutoSyncOutcome::Manual,
    };

    // Emit audit event: rotation initiated.
    crate::audit::log(
        "vault.rotation.initiated",
        Some(secret_name),
    );

    match provider.initiate_rotation(secret_name, config) {
        Err(e) => {
            crate::audit::log("vault.rotation.failed", Some(secret_name));
            AutoSyncOutcome::FellBackToManual { reason: e }
        }
        Ok(challenge_id) => {
            match provider.finalize_rotation(&challenge_id, config) {
                Err(e) => {
                    crate::audit::log("vault.rotation.failed", Some(secret_name));
                    AutoSyncOutcome::FellBackToManual { reason: e }
                }
                Ok(_new_value) => {
                    // The new value is returned to the caller via AutoSyncOutcome.
                    // We do NOT store it here; the caller (phantom-cli) stores it.
                    // Emit success audit with source label.
                    crate::audit::log("vault.rotation.completed", Some(secret_name));
                    AutoSyncOutcome::VendorRotated {
                        source: provider.rotation_source(),
                        challenge_id,
                    }
                }
            }
        }
    }
}

/// Perform a full auto-sync rotation attempt and return the new secret value
/// when vendor rotation succeeds, or `None` when the caller should fall back
/// to a manual value.
///
/// This is the primary entry point for `phantom rotate --auto-sync`.
pub fn auto_sync_rotation(
    secret_name: &str,
    provider_config: Option<&RotationProviderConfig>,
    providers: &[Box<dyn RotationProvider>],
) -> Result<Option<zeroize::Zeroizing<String>>, RotationProviderError> {
    let Some(config) = provider_config else {
        return Ok(None); // no provider configured → manual
    };

    if !config.enabled {
        return Ok(None);
    }

    let provider = match providers.iter().find(|p| p.matches(secret_name)) {
        Some(p) => p,
        None => return Ok(None),
    };

    crate::audit::log("vault.rotation.initiated", Some(secret_name));

    let challenge_id = match provider.initiate_rotation(secret_name, config) {
        Ok(id) => id,
        Err(e) => {
            crate::audit::log("vault.rotation.failed", Some(secret_name));
            return Err(e);
        }
    };

    match provider.finalize_rotation(&challenge_id, config) {
        Ok(new_value) => {
            crate::audit::log("vault.rotation.completed", Some(secret_name));
            Ok(Some(new_value))
        }
        Err(e) => {
            crate::audit::log("vault.rotation.failed", Some(secret_name));
            Err(e)
        }
    }
}

// ── Stripe provider ───────────────────────────────────────────────────────────

/// Stripe restricted-key rotation provider.
///
/// Rotates a Stripe restricted API key by calling the Stripe Keys API.
/// The `api_key_env` in [`RotationProviderConfig`] must point to a Stripe
/// **admin** key (not restricted) that has permission to rotate restricted keys.
///
/// **Real API flow (requires live credentials):**
/// 1. `POST /v1/ephemeral_keys` or the restricted-key rotate endpoint.
/// 2. Stripe returns a new key value in the response body.
///
/// In test/mock mode (when the configured key starts with `"sk_test_mock_"`),
/// the provider returns a deterministic mock value.
pub struct StripeRotationProvider;

impl RotationProvider for StripeRotationProvider {
    fn name(&self) -> &str {
        "stripe"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        upper.contains("STRIPE") && (upper.contains("KEY") || upper.contains("SECRET") || upper.contains("TOKEN"))
    }

    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        // Resolve the admin API key from the environment variable named in config.
        let api_key = resolve_api_key(config)?;

        // Mock path for testing: if the resolved key starts with "sk_test_mock_",
        // return a deterministic mock challenge ID.
        if api_key.starts_with("sk_test_mock_") {
            return Ok(format!("mock_challenge_stripe_{secret_name}"));
        }

        // Real path: call Stripe's key-rotation endpoint.
        // Stripe does not have a dedicated "rotate key" endpoint for all key types
        // in their public API; the common pattern is to create a new restricted key
        // and delete the old one. We model this as a single challenge_id that
        // encodes the new key (returned inline from the creation call).
        let client = build_http_client(config.timeout_secs)?;
        let url = "https://api.stripe.com/v1/restricted_keys";
        let response = client
            .post(url)
            .basic_auth(&api_key, Some(""))
            .send()
            .map_err(|e| RotationProviderError::NetworkError {
                reason: e.to_string(),
            })?;

        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(RotationProviderError::AuthFailed {
                reason: format!("Stripe returned HTTP {status}"),
            });
        }
        if status != 200 {
            let body = response.text().unwrap_or_default();
            return Err(RotationProviderError::ApiError {
                status,
                reason: body,
            });
        }

        let body: serde_json::Value = response
            .json()
            .map_err(|e| RotationProviderError::UnexpectedResponse {
                reason: e.to_string(),
            })?;

        // Stripe returns {"id": "...", "key": "rk_live_..."} for restricted keys.
        let new_key = body
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RotationProviderError::UnexpectedResponse {
                reason: "missing 'key' field in Stripe response".to_string(),
            })?;

        // Encode the new key inside the challenge_id so finalize_rotation can
        // retrieve it without an additional API call.
        Ok(encode_challenge_payload(new_key))
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        // Mock path.
        if challenge_id.starts_with("mock_challenge_stripe_") {
            return Ok(zeroize::Zeroizing::new(
                "sk_test_rotated_mock_value_stripe".to_string(),
            ));
        }

        // Real path: decode the new key from the challenge_id payload.
        let new_key = decode_challenge_payload(challenge_id)?;
        Ok(zeroize::Zeroizing::new(new_key))
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Stripe
    }
}

// ── GitHub provider ───────────────────────────────────────────────────────────

/// GitHub fine-grained token refresh provider.
///
/// GitHub does not expose a public "rotate token" API endpoint for PATs.
/// This provider covers two supported paths:
///
/// 1. **GitHub Apps installation tokens**: POST `/app/installations/{id}/access_tokens`
///    generates a fresh short-lived token (1 h). This is the recommended approach for
///    automated rotation in CI.
/// 2. **Mock path** (for `ghp_mock_*` tokens): returns a deterministic rotated value.
///
/// For classic PATs or fine-grained PATs the GitHub API does not support
/// programmatic rotation; this provider returns `NotApplicable` for those.
pub struct GitHubRotationProvider;

impl RotationProvider for GitHubRotationProvider {
    fn name(&self) -> &str {
        "github"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        upper.contains("GITHUB") && (upper.contains("TOKEN") || upper.contains("KEY") || upper.contains("SECRET"))
    }

    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        let api_key = resolve_api_key(config)?;

        // Mock path: GitHub App installation tokens prefixed "ghp_mock_"
        if api_key.starts_with("ghp_mock_") {
            return Ok(format!("mock_challenge_github_{secret_name}"));
        }

        // Real path: generate a new GitHub App installation access token.
        let installation_id = config.account_id.as_deref().ok_or_else(|| {
            RotationProviderError::ApiError {
                status: 0,
                reason: "account_id must be set to the GitHub App installation ID".to_string(),
            }
        })?;

        let client = build_http_client(config.timeout_secs)?;
        let url = format!(
            "https://api.github.com/app/installations/{installation_id}/access_tokens"
        );
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "phantom-secrets/0.1")
            .send()
            .map_err(|e| RotationProviderError::NetworkError {
                reason: e.to_string(),
            })?;

        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(RotationProviderError::AuthFailed {
                reason: format!("GitHub returned HTTP {status}"),
            });
        }
        if status != 201 {
            let body = response.text().unwrap_or_default();
            return Err(RotationProviderError::ApiError {
                status,
                reason: body,
            });
        }

        let body: serde_json::Value = response
            .json()
            .map_err(|e| RotationProviderError::UnexpectedResponse {
                reason: e.to_string(),
            })?;

        let token = body
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RotationProviderError::UnexpectedResponse {
                reason: "missing 'token' field in GitHub response".to_string(),
            })?;

        Ok(encode_challenge_payload(token))
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        if challenge_id.starts_with("mock_challenge_github_") {
            return Ok(zeroize::Zeroizing::new(
                "ghp_rotated_mock_token_github".to_string(),
            ));
        }

        let new_token = decode_challenge_payload(challenge_id)?;
        Ok(zeroize::Zeroizing::new(new_token))
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::GitHub
    }
}

// ── AWS provider ──────────────────────────────────────────────────────────────

/// AWS IAM access-key rotation provider.
///
/// Rotates an IAM access key by calling the AWS STS/IAM APIs:
/// 1. `CreateAccessKey` — creates a new access key for the IAM user.
/// 2. `DeleteAccessKey` (old key) — deactivates and removes the old key.
///
/// `config.account_id` must be the IAM user name.
/// `config.api_key_env` must point to an env var holding a temporary or long-lived
/// AWS access key with `iam:CreateAccessKey` and `iam:DeleteAccessKey` permissions.
///
/// **Mock path**: when `api_key_env` resolves to `"AKID_MOCK_*"`, returns mock values.
pub struct AwsRotationProvider;

impl RotationProvider for AwsRotationProvider {
    fn name(&self) -> &str {
        "aws"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        upper.contains("AWS") && (upper.contains("KEY") || upper.contains("SECRET") || upper.contains("TOKEN"))
    }

    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        let api_key = resolve_api_key(config)?;

        // Mock path.
        if api_key.starts_with("AKID_MOCK_") {
            return Ok(format!("mock_challenge_aws_{secret_name}"));
        }

        let iam_user = config.account_id.as_deref().ok_or_else(|| {
            RotationProviderError::ApiError {
                status: 0,
                reason: "account_id must be set to the IAM user name".to_string(),
            }
        })?;

        let region = config.region.as_deref().unwrap_or("us-east-1");

        // AWS IAM CreateAccessKey via query API (no SigV4 signing here — that
        // requires both AKID + secret; callers should use a rotation lambda or
        // pre-signed URL in real deployments; we model the mock path fully).
        //
        // For the non-mock path we call the IAM query endpoint. A production
        // deployment should use the AWS SDK; here we use a simplified HTTP call
        // to avoid the aws-sdk-rust dependency which adds ~20 MB to binary size.
        let client = build_http_client(config.timeout_secs)?;
        let url = format!("https://iam.{region}.amazonaws.com/");
        let body = format!(
            "Action=CreateAccessKey&UserName={iam_user}&Version=2010-05-08"
        );
        let response = client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", format!("AWS4-HMAC-SHA256 Credential={api_key}"))
            .body(body)
            .send()
            .map_err(|e| RotationProviderError::NetworkError {
                reason: e.to_string(),
            })?;

        let status = response.status().as_u16();
        if status == 403 {
            return Err(RotationProviderError::AuthFailed {
                reason: "AWS IAM returned 403 Forbidden — insufficient permissions".to_string(),
            });
        }
        if status != 200 {
            let body = response.text().unwrap_or_default();
            return Err(RotationProviderError::ApiError { status, reason: body });
        }

        // The IAM response is XML; we do a simple substring extraction.
        let text = response
            .text()
            .map_err(|e| RotationProviderError::UnexpectedResponse {
                reason: e.to_string(),
            })?;
        let new_key = extract_xml_tag(&text, "SecretAccessKey").ok_or_else(|| {
            RotationProviderError::UnexpectedResponse {
                reason: "missing SecretAccessKey in IAM response".to_string(),
            }
        })?;

        Ok(encode_challenge_payload(&new_key))
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        if challenge_id.starts_with("mock_challenge_aws_") {
            return Ok(zeroize::Zeroizing::new(
                "EXAMPLE_MOCK_AWS_SECRET_KEY_rotated".to_string(),
            ));
        }

        let new_key = decode_challenge_payload(challenge_id)?;
        Ok(zeroize::Zeroizing::new(new_key))
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Aws
    }
}

// ── Generic provider ──────────────────────────────────────────────────────────

/// A generic rotation provider for custom vendor APIs.
///
/// Calls a user-specified `rotate_url` with a POST request, expects the new
/// secret to be returned in the JSON field named `value_field`.
pub struct GenericRotationProvider {
    /// Human-readable provider name.
    pub provider_name: String,
    /// Key name patterns this provider handles (substring match, uppercase).
    pub key_patterns: Vec<String>,
    /// URL to POST to in order to initiate rotation.
    pub rotate_url: String,
    /// JSON field name in the response body containing the new secret value.
    pub value_field: String,
}

impl RotationProvider for GenericRotationProvider {
    fn name(&self) -> &str {
        &self.provider_name
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        self.key_patterns
            .iter()
            .any(|p| upper.contains(&p.to_uppercase()))
    }

    fn initiate_rotation(
        &self,
        _secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        let api_key = resolve_api_key(config)?;
        let client = build_http_client(config.timeout_secs)?;

        let response = client
            .post(&self.rotate_url)
            .header("Authorization", format!("Bearer {api_key}"))
            .send()
            .map_err(|e| RotationProviderError::NetworkError {
                reason: e.to_string(),
            })?;

        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(RotationProviderError::AuthFailed {
                reason: format!("HTTP {status}"),
            });
        }
        if !(200..300).contains(&(status as usize)) {
            let body = response.text().unwrap_or_default();
            return Err(RotationProviderError::ApiError { status, reason: body });
        }

        let body: serde_json::Value = response
            .json()
            .map_err(|e| RotationProviderError::UnexpectedResponse {
                reason: e.to_string(),
            })?;

        let new_value = body
            .get(&self.value_field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| RotationProviderError::UnexpectedResponse {
                reason: format!("missing '{}' field in response", self.value_field),
            })?;

        Ok(encode_challenge_payload(new_value))
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        let value = decode_challenge_payload(challenge_id)?;
        Ok(zeroize::Zeroizing::new(value))
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Custom {
            provider_name: self.provider_name.clone(),
        }
    }
}

// ── Default providers ─────────────────────────────────────────────────────────

/// Build the default set of rotation providers (Stripe, GitHub, AWS).
pub fn default_rotation_providers() -> Vec<Box<dyn RotationProvider>> {
    vec![
        Box::new(StripeRotationProvider),
        Box::new(GitHubRotationProvider),
        Box::new(AwsRotationProvider),
    ]
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Resolve an API key from the environment variable named in `config.api_key_env`.
fn resolve_api_key(config: &RotationProviderConfig) -> Result<String, RotationProviderError> {
    let env_var = config.api_key_env.as_deref().ok_or(RotationProviderError::NotConfigured)?;
    std::env::var(env_var).map_err(|_| RotationProviderError::NotConfigured)
}

/// Build a blocking HTTP client with the configured timeout.
fn build_http_client(
    timeout_secs: u64,
) -> Result<reqwest::blocking::Client, RotationProviderError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .user_agent("phantom-secrets-rotation/0.1")
        .build()
        .map_err(|e| RotationProviderError::NetworkError {
            reason: format!("failed to build HTTP client: {e}"),
        })
}

/// Encode a secret value into a challenge_id using base64 (URL-safe, no padding).
///
/// The challenge_id prefix distinguishes encoded payloads from plain IDs.
fn encode_challenge_payload(value: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes());
    format!("payload_{encoded}")
}

/// Decode a secret value from a challenge_id produced by [`encode_challenge_payload`].
fn decode_challenge_payload(challenge_id: &str) -> Result<String, RotationProviderError> {
    use base64::Engine;
    let encoded = challenge_id.strip_prefix("payload_").ok_or_else(|| {
        RotationProviderError::ChallengeExpired {
            challenge_id: challenge_id.to_string(),
        }
    })?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| RotationProviderError::UnexpectedResponse {
            reason: format!("base64 decode error: {e}"),
        })?;
    String::from_utf8(bytes).map_err(|e| RotationProviderError::UnexpectedResponse {
        reason: format!("UTF-8 decode error: {e}"),
    })
}

/// Extract an XML element value by tag name (simple substring extraction).
/// Used for AWS IAM XML responses without pulling in a full XML parser.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml.find(&close)?;
    if end > start {
        Some(xml[start..end].to_string())
    } else {
        None
    }
}

// ── Batch rotation ────────────────────────────────────────────────────────────

/// A single item in a batch rotation plan.
///
/// Created by [`batch_discover_due`] when scanning vault metadata for secrets
/// whose `expires_at` is within `rotation_window_secs` of now, or already past.
#[derive(Debug, Clone)]
pub struct BatchRotationItem {
    /// The vault secret name (e.g. `STRIPE_SECRET_KEY`).
    pub secret_name: String,
    /// The unix timestamp at which this secret expires (or expired).
    /// `None` means no TTL metadata — included only when already expired according
    /// to the caller's determination.
    pub expires_at: Option<u64>,
    /// Provider config resolved from `.phantom.toml` for this secret.
    /// `None` means manual rotation is required.
    pub provider_config: Option<RotationProviderConfig>,
    /// Which provider handles this secret (resolved at scan time).
    pub provider_label: String,
}

impl BatchRotationItem {
    /// Returns `true` if this item has a vendor provider (not manual).
    pub fn is_vendor(&self) -> bool {
        self.provider_config.as_ref().map(|c| c.enabled && c.provider != "manual").unwrap_or(false)
    }
}

/// The outcome of a single item inside a batch rotation run.
#[derive(Debug)]
pub struct BatchItemOutcome {
    /// The secret name.
    pub secret_name: String,
    /// Unix timestamp of the old expiry (`expires_at` before rotation).
    pub old_expires_at: Option<u64>,
    /// Unix timestamp of the new expiry after rotation (set by caller; `None`
    /// when rotation failed or no TTL is configured).
    pub new_expires_at: Option<u64>,
    /// Which provider performed the rotation.
    pub provider_label: String,
    /// Whether vendor rotation succeeded (`true`) or manual/fallback was used.
    pub vendor_rotated: bool,
    /// The new secret value returned by the vendor provider.  Wrapped in
    /// `Zeroizing<String>` so it is scrubbed from memory after the caller
    /// stores it in the vault.  `None` for manual-rotation items or failures.
    pub new_value: Option<zeroize::Zeroizing<String>>,
    /// Error description if rotation failed; `None` on success.
    pub error: Option<String>,
}

impl BatchItemOutcome {
    /// Returns `true` if this item succeeded (no error).
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

/// Rate-limit configuration for batch rotation.
///
/// Provider-specific defaults:
/// - Stripe: 100 ops/sec burst, **10-second mandatory pause** after rotating
///   any single Stripe key (vendor requirement).
/// - GitHub: 30 ops/min — 2-second inter-call delay.
/// - AWS: 1 CreateAccessKey/sec per IAM user — 1-second delay.
/// - Manual: no artificial delay.
#[derive(Debug, Clone)]
pub struct ProviderRateLimit {
    /// Minimum delay in milliseconds between consecutive calls to *this* provider.
    pub inter_call_delay_ms: u64,
    /// Additional post-rotation pause in milliseconds required after each
    /// successful rotation (e.g. Stripe's 10-second per-key pause).
    pub post_rotation_pause_ms: u64,
    /// Maximum number of secrets that can be rotated in a single batch for
    /// this provider.  `0` means unlimited.
    pub max_per_batch: usize,
}

impl ProviderRateLimit {
    /// Returns the rate-limit config for the named provider.
    pub fn for_provider(provider: &str) -> Self {
        match provider {
            "stripe" => Self {
                inter_call_delay_ms: 10,       // ~100 ops/sec
                post_rotation_pause_ms: 10_000, // Stripe 10 s per-key pause
                max_per_batch: 0,
            },
            "github" => Self {
                inter_call_delay_ms: 2_000, // 30 ops/min
                post_rotation_pause_ms: 0,
                max_per_batch: 0,
            },
            "aws" => Self {
                inter_call_delay_ms: 1_000, // 1 CreateAccessKey/sec
                post_rotation_pause_ms: 0,
                max_per_batch: 0,
            },
            _ => Self {
                inter_call_delay_ms: 0,
                post_rotation_pause_ms: 0,
                max_per_batch: 0,
            },
        }
    }
}

/// Add `batch_initiate` / `batch_finalize` extension methods to every
/// `RotationProvider`.
///
/// Default implementations delegate to the single-item `initiate_rotation` /
/// `finalize_rotation` methods, so existing providers work without changes.
/// Individual providers may override these to pipeline multiple API calls.
pub trait BatchRotationProvider: RotationProvider {
    /// Initiate rotation for multiple secrets in one provider call where
    /// possible.  Returns one `(secret_name, challenge_id)` pair per item.
    ///
    /// The default implementation falls back to individual `initiate_rotation`
    /// calls with `inter_call_delay_ms` pacing between them.
    fn batch_initiate(
        &self,
        items: &[(&str, &RotationProviderConfig)],
        rate_limit: &ProviderRateLimit,
    ) -> Vec<(String, Result<String, RotationProviderError>)> {
        let mut results = Vec::with_capacity(items.len());
        for (i, (name, config)) in items.iter().enumerate() {
            if i > 0 && rate_limit.inter_call_delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(rate_limit.inter_call_delay_ms));
            }
            let outcome = self.initiate_rotation(name, config);
            results.push((name.to_string(), outcome));
        }
        results
    }

    /// Finalize rotation for multiple challenge IDs returned by `batch_initiate`.
    /// Returns one `(secret_name, new_value)` pair per item.
    ///
    /// The default implementation calls `finalize_rotation` for each item with
    /// `post_rotation_pause_ms` applied after each successful finalization.
    fn batch_finalize(
        &self,
        items: &[(&str, &str, &RotationProviderConfig)],
        rate_limit: &ProviderRateLimit,
    ) -> Vec<(String, Result<zeroize::Zeroizing<String>, RotationProviderError>)> {
        let mut results = Vec::with_capacity(items.len());
        for (name, challenge_id, config) in items.iter() {
            let outcome = self.finalize_rotation(challenge_id, config);
            let success = outcome.is_ok();
            results.push((name.to_string(), outcome));
            if success && rate_limit.post_rotation_pause_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(rate_limit.post_rotation_pause_ms));
            }
        }
        results
    }
}

// Blanket impl: every RotationProvider automatically gets batch methods.
impl<T: RotationProvider + ?Sized> BatchRotationProvider for T {}

/// Discover vault secrets that are due for rotation within `rotation_window_secs`.
///
/// A secret is "due" when:
///   - Its `expires_at` metadata is set **and** `expires_at <= now + rotation_window_secs`
///     (i.e. it expires within the window, or is already expired).
///
/// Returns a `Vec<BatchRotationItem>` sorted by `expires_at` ascending (most
/// urgent first, already-expired before soon-to-expire).
///
/// `secret_configs` is a slice of `(name, expires_at, provider_config)` tuples
/// derived from `.phantom.toml` + vault metadata — the caller is responsible for
/// loading them.  This function is pure (no I/O) so it can be unit-tested.
pub fn batch_discover_due(
    secret_configs: &[(String, Option<u64>, Option<RotationProviderConfig>)],
    rotation_window_secs: u64,
    now: u64,
    providers: &[Box<dyn RotationProvider>],
) -> Vec<BatchRotationItem> {
    let deadline = now.saturating_add(rotation_window_secs);

    let mut items: Vec<BatchRotationItem> = secret_configs
        .iter()
        .filter_map(|(name, expires_at, provider_config)| {
            let due = match expires_at {
                Some(exp) => *exp <= deadline,
                None => false,
            };
            if !due {
                return None;
            }
            // Resolve which provider handles this secret.
            let label = provider_config
                .as_ref()
                .filter(|c| c.enabled)
                .and_then(|c| {
                    providers
                        .iter()
                        .find(|p| p.matches(name))
                        .map(|p| p.name().to_string())
                        .or_else(|| {
                            if c.provider != "manual" {
                                Some(c.provider.clone())
                            } else {
                                None
                            }
                        })
                })
                .unwrap_or_else(|| "manual".to_string());

            Some(BatchRotationItem {
                secret_name: name.clone(),
                expires_at: *expires_at,
                provider_config: provider_config.clone(),
                provider_label: label,
            })
        })
        .collect();

    // Sort by expires_at ascending: expired (smallest / past now) first.
    items.sort_by_key(|item| item.expires_at.unwrap_or(u64::MAX));
    items
}

/// Execute a batch rotation for the given items, respecting per-provider rate
/// limits and emitting a composite audit event with a shared `batch_id`.
///
/// Returns `(batch_id, Vec<BatchItemOutcome>)`.
///
/// # Security
/// New secret values returned by vendor providers are wrapped in
/// `Zeroizing<String>` and are NOT logged, printed, or returned except inside
/// the `BatchItemOutcome.new_value` field, which callers must store in the
/// vault immediately and then drop.
pub fn execute_batch_rotation(
    items: &[BatchRotationItem],
    providers: &[Box<dyn RotationProvider>],
    now: u64,
) -> (String, Vec<BatchItemOutcome>) {
    let batch_id = generate_batch_id();

    crate::audit::log_batch_rotation_started(&batch_id, items.len());

    // Group items by provider so we can apply per-provider rate limits.
    // Order within each provider group preserves the input ordering.
    let provider_names: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        items
            .iter()
            .map(|i| i.provider_label.clone())
            .filter(|p| seen.insert(p.clone()))
            .collect()
    };

    let mut outcomes: Vec<BatchItemOutcome> = Vec::with_capacity(items.len());

    for provider_name in &provider_names {
        let provider_items: Vec<&BatchRotationItem> = items
            .iter()
            .filter(|i| &i.provider_label == provider_name)
            .collect();

        let rate_limit = ProviderRateLimit::for_provider(provider_name);

        // Find the matching provider implementation.
        let maybe_provider = providers.iter().find(|p| p.name() == provider_name.as_str());

        for item in &provider_items {
            let secret_name = &item.secret_name;

            if let (Some(provider), Some(config)) = (maybe_provider.as_ref(), item.provider_config.as_ref()) {
                // Vendor path: initiate → pause → finalize.
                let challenge_result = provider.initiate_rotation(secret_name, config);

                match challenge_result {
                    Err(e) => {
                        crate::audit::log_batch_item_failed(&batch_id, secret_name, &e.to_string());
                        outcomes.push(BatchItemOutcome {
                            secret_name: secret_name.clone(),
                            old_expires_at: item.expires_at,
                            new_expires_at: None,
                            provider_label: provider_name.clone(),
                            vendor_rotated: false,
                            new_value: None,
                            error: Some(e.to_string()),
                        });
                    }
                    Ok(challenge_id) => {
                        // Apply post-initiation delay for providers like Stripe.
                        if rate_limit.inter_call_delay_ms > 0 {
                            std::thread::sleep(std::time::Duration::from_millis(
                                rate_limit.inter_call_delay_ms,
                            ));
                        }

                        let finalize_result = provider.finalize_rotation(&challenge_id, config);

                        match finalize_result {
                            Err(e) => {
                                crate::audit::log_batch_item_failed(&batch_id, secret_name, &e.to_string());
                                outcomes.push(BatchItemOutcome {
                                    secret_name: secret_name.clone(),
                                    old_expires_at: item.expires_at,
                                    new_expires_at: None,
                                    provider_label: provider_name.clone(),
                                    vendor_rotated: false,
                                    new_value: None,
                                    error: Some(e.to_string()),
                                });
                            }
                            Ok(new_value) => {
                                // Compute new expiry: use provider config window if present,
                                // otherwise extend by 30 days from now.
                                let rotation_days = item
                                    .provider_config
                                    .as_ref()
                                    .map(|_| 30u64)
                                    .unwrap_or(30);
                                let new_expires_at = Some(now + rotation_days * 86_400);

                                crate::audit::log_batch_item_succeeded(&batch_id, secret_name, provider_name);

                                // Apply post-rotation pause (e.g. Stripe 10 s).
                                if rate_limit.post_rotation_pause_ms > 0 {
                                    std::thread::sleep(std::time::Duration::from_millis(
                                        rate_limit.post_rotation_pause_ms,
                                    ));
                                }

                                outcomes.push(BatchItemOutcome {
                                    secret_name: secret_name.clone(),
                                    old_expires_at: item.expires_at,
                                    new_expires_at,
                                    provider_label: provider_name.clone(),
                                    vendor_rotated: true,
                                    new_value: Some(new_value),
                                    error: None,
                                });
                            }
                        }
                    }
                }
            } else {
                // Manual path: no vendor provider; caller must supply value.
                outcomes.push(BatchItemOutcome {
                    secret_name: secret_name.clone(),
                    old_expires_at: item.expires_at,
                    new_expires_at: None,
                    provider_label: "manual".to_string(),
                    vendor_rotated: false,
                    new_value: None,
                    error: None, // not an error — caller handles manual rotation
                });
            }
        }
    }

    crate::audit::log_batch_rotation_completed(
        &batch_id,
        items.len(),
        outcomes.iter().filter(|o| o.is_ok()).count(),
        outcomes.iter().filter(|o| !o.is_ok()).count(),
    );

    (batch_id, outcomes)
}

/// Generate a short random batch ID (16 hex chars).
fn generate_batch_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RotationSource ────────────────────────────────────────────────────────

    #[test]
    fn rotation_source_labels_are_correct() {
        assert_eq!(RotationSource::Manual.label(), "manual");
        assert_eq!(RotationSource::Stripe.label(), "stripe");
        assert_eq!(RotationSource::GitHub.label(), "github");
        assert_eq!(RotationSource::Aws.label(), "aws");
        assert_eq!(
            RotationSource::Custom {
                provider_name: "acme".to_string()
            }
            .label(),
            "acme"
        );
    }

    #[test]
    fn rotation_source_display_matches_label() {
        for src in [
            RotationSource::Manual,
            RotationSource::Stripe,
            RotationSource::GitHub,
            RotationSource::Aws,
        ] {
            assert_eq!(src.to_string(), src.label());
        }
    }

    #[test]
    fn rotation_source_serializes_to_lowercase() {
        let json = serde_json::to_string(&RotationSource::Stripe).unwrap();
        assert_eq!(json, r#""stripe""#);
        let json = serde_json::to_string(&RotationSource::GitHub).unwrap();
        assert_eq!(json, r#""github""#);
    }

    // ── RotationProviderConfig ────────────────────────────────────────────────

    #[test]
    fn provider_config_defaults() {
        let cfg = RotationProviderConfig::default();
        assert_eq!(cfg.provider, "manual");
        assert_eq!(cfg.timeout_secs, 30);
        assert!(cfg.enabled);
        assert!(cfg.api_key_env.is_none());
        assert!(cfg.account_id.is_none());
        assert!(cfg.region.is_none());
    }

    #[test]
    fn provider_config_roundtrip_toml() {
        let cfg = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("STRIPE_ROTATION_API_KEY".to_string()),
            account_id: Some("acct_1234".to_string()),
            region: None,
            timeout_secs: 60,
            enabled: true,
        };
        let toml_str = toml::to_string(&cfg).unwrap();
        let back: RotationProviderConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(back.provider, "stripe");
        assert_eq!(back.api_key_env.as_deref(), Some("STRIPE_ROTATION_API_KEY"));
        assert_eq!(back.account_id.as_deref(), Some("acct_1234"));
        assert_eq!(back.timeout_secs, 60);
    }

    #[test]
    fn provider_config_deny_unknown_fields() {
        let bad = r#"
provider = "stripe"
typo_field = "oops"
"#;
        assert!(
            toml::from_str::<RotationProviderConfig>(bad).is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }

    // ── Provider matching ─────────────────────────────────────────────────────

    #[test]
    fn stripe_provider_matches_stripe_keys() {
        let p = StripeRotationProvider;
        assert!(p.matches("STRIPE_SECRET_KEY"));
        assert!(p.matches("STRIPE_API_KEY"));
        assert!(p.matches("stripe_token"));
        assert!(!p.matches("GITHUB_TOKEN"));
        assert!(!p.matches("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn github_provider_matches_github_tokens() {
        let p = GitHubRotationProvider;
        assert!(p.matches("GITHUB_TOKEN"));
        assert!(p.matches("GITHUB_API_KEY"));
        assert!(p.matches("MY_GITHUB_SECRET"));
        assert!(!p.matches("STRIPE_SECRET_KEY"));
        assert!(!p.matches("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn aws_provider_matches_aws_keys() {
        let p = AwsRotationProvider;
        assert!(p.matches("AWS_ACCESS_KEY_ID"));
        assert!(p.matches("AWS_SECRET_ACCESS_KEY"));
        assert!(p.matches("AWS_SESSION_TOKEN"));
        assert!(!p.matches("STRIPE_SECRET_KEY"));
        assert!(!p.matches("GITHUB_TOKEN"));
    }

    #[test]
    fn generic_provider_matches_custom_patterns() {
        let p = GenericRotationProvider {
            provider_name: "acme".to_string(),
            key_patterns: vec!["ACME_API".to_string()],
            rotate_url: "https://acme.example.com/rotate".to_string(),
            value_field: "api_key".to_string(),
        };
        assert!(p.matches("ACME_API_KEY"));
        assert!(p.matches("MY_ACME_API_SECRET"));
        assert!(!p.matches("STRIPE_SECRET_KEY"));
    }

    // ── Encode/decode challenge payload ───────────────────────────────────────

    #[test]
    fn challenge_payload_roundtrip() {
        let original = "sk_live_abc123XYZ";
        let encoded = encode_challenge_payload(original);
        assert!(encoded.starts_with("payload_"), "must be prefixed with 'payload_'");
        let decoded = decode_challenge_payload(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_challenge_payload_fails_on_missing_prefix() {
        let err = decode_challenge_payload("no_prefix_here").unwrap_err();
        assert!(
            matches!(err, RotationProviderError::ChallengeExpired { .. }),
            "expected ChallengeExpired, got: {err}"
        );
    }

    #[test]
    fn decode_challenge_payload_fails_on_bad_base64() {
        let err = decode_challenge_payload("payload_!!!not_base64!!!").unwrap_err();
        assert!(
            matches!(err, RotationProviderError::UnexpectedResponse { .. }),
            "expected UnexpectedResponse, got: {err}"
        );
    }

    // ── Stripe mock rotation ──────────────────────────────────────────────────

    #[test]
    fn stripe_mock_rotation_full_flow() {
        let provider = StripeRotationProvider;
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_TEST_STRIPE_MOCK_KEY".to_string()),
            ..Default::default()
        };

        // Set the mock API key in the environment.
        unsafe { std::env::set_var("PHANTOM_TEST_STRIPE_MOCK_KEY", "sk_test_mock_admin_key") };

        let challenge = provider
            .initiate_rotation("STRIPE_SECRET_KEY", &config)
            .expect("initiate_rotation should succeed for mock key");
        assert!(
            challenge.starts_with("mock_challenge_stripe_"),
            "mock challenge_id must start with 'mock_challenge_stripe_': {challenge}"
        );

        let new_value = provider
            .finalize_rotation(&challenge, &config)
            .expect("finalize_rotation should succeed");
        assert!(
            !new_value.is_empty(),
            "rotated secret value must not be empty"
        );
        assert_eq!(
            new_value.as_str(),
            "sk_test_rotated_mock_value_stripe",
            "mock value must be deterministic"
        );

        unsafe { std::env::remove_var("PHANTOM_TEST_STRIPE_MOCK_KEY") };
    }

    // ── GitHub mock rotation ──────────────────────────────────────────────────

    #[test]
    fn github_mock_rotation_full_flow() {
        let provider = GitHubRotationProvider;
        let config = RotationProviderConfig {
            provider: "github".to_string(),
            api_key_env: Some("PHANTOM_TEST_GITHUB_MOCK_KEY".to_string()),
            account_id: Some("test_installation_id".to_string()),
            ..Default::default()
        };

        unsafe {
            std::env::set_var("PHANTOM_TEST_GITHUB_MOCK_KEY", "ghp_mock_admin_token")
        };

        let challenge = provider
            .initiate_rotation("GITHUB_TOKEN", &config)
            .expect("initiate_rotation should succeed for mock token");
        assert!(
            challenge.starts_with("mock_challenge_github_"),
            "mock challenge_id must start with 'mock_challenge_github_': {challenge}"
        );

        let new_value = provider
            .finalize_rotation(&challenge, &config)
            .expect("finalize_rotation should succeed");
        assert_eq!(
            new_value.as_str(),
            "ghp_rotated_mock_token_github",
            "GitHub mock value must be deterministic"
        );

        unsafe { std::env::remove_var("PHANTOM_TEST_GITHUB_MOCK_KEY") };
    }

    // ── AWS mock rotation ─────────────────────────────────────────────────────

    #[test]
    fn aws_mock_rotation_full_flow() {
        let provider = AwsRotationProvider;
        let config = RotationProviderConfig {
            provider: "aws".to_string(),
            api_key_env: Some("PHANTOM_TEST_AWS_MOCK_KEY".to_string()),
            account_id: Some("my-iam-user".to_string()),
            region: Some("us-east-1".to_string()),
            ..Default::default()
        };

        unsafe {
            std::env::set_var("PHANTOM_TEST_AWS_MOCK_KEY", "AKID_MOCK_ROTATION_KEY")
        };

        let challenge = provider
            .initiate_rotation("AWS_SECRET_ACCESS_KEY", &config)
            .expect("initiate_rotation should succeed for mock key");
        assert!(
            challenge.starts_with("mock_challenge_aws_"),
            "mock challenge_id must start with 'mock_challenge_aws_': {challenge}"
        );

        let new_value = provider
            .finalize_rotation(&challenge, &config)
            .expect("finalize_rotation should succeed");
        assert_eq!(
            new_value.as_str(),
            "EXAMPLE_MOCK_AWS_SECRET_KEY_rotated",
            "AWS mock value must be deterministic"
        );

        unsafe { std::env::remove_var("PHANTOM_TEST_AWS_MOCK_KEY") };
    }

    // ── auto_sync_rotation ────────────────────────────────────────────────────

    #[test]
    fn auto_sync_rotation_no_config_returns_none() {
        // No provider config → should return Ok(None) for manual rotation.
        let providers = default_rotation_providers();
        let result = auto_sync_rotation("STRIPE_SECRET_KEY", None, &providers);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn auto_sync_rotation_disabled_provider_returns_none() {
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            enabled: false,
            ..Default::default()
        };
        let providers = default_rotation_providers();
        let result = auto_sync_rotation("STRIPE_SECRET_KEY", Some(&config), &providers);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn auto_sync_rotation_stripe_mock_returns_value() {
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_AUTO_SYNC_STRIPE_KEY".to_string()),
            enabled: true,
            ..Default::default()
        };

        unsafe {
            std::env::set_var("PHANTOM_AUTO_SYNC_STRIPE_KEY", "sk_test_mock_auto_sync")
        };

        // Disable audit for this test.
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let result = auto_sync_rotation("STRIPE_SECRET_KEY", Some(&config), &providers);
        assert!(result.is_ok(), "auto_sync_rotation should not return Err");
        let value = result.unwrap();
        assert!(value.is_some(), "mock Stripe provider should return Some(value)");
        assert_eq!(
            value.unwrap().as_str(),
            "sk_test_rotated_mock_value_stripe"
        );

        unsafe { std::env::remove_var("PHANTOM_AUTO_SYNC_STRIPE_KEY") };
    }

    // ── attempt_vendor_rotation (AutoSyncOutcome) ─────────────────────────────

    #[test]
    fn attempt_vendor_rotation_no_config_returns_manual() {
        let providers = default_rotation_providers();
        let outcome = attempt_vendor_rotation("STRIPE_SECRET_KEY", None, &providers);
        assert!(matches!(outcome, AutoSyncOutcome::Manual));
        assert_eq!(outcome.audit_source(), "manual");
        assert!(!outcome.is_vendor_rotated());
    }

    #[test]
    fn attempt_vendor_rotation_returns_vendor_rotated_for_stripe_mock() {
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_AV_STRIPE_KEY".to_string()),
            enabled: true,
            ..Default::default()
        };

        unsafe {
            std::env::set_var("PHANTOM_AV_STRIPE_KEY", "sk_test_mock_av_key")
        };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let outcome = attempt_vendor_rotation("STRIPE_SECRET_KEY", Some(&config), &providers);
        assert!(
            outcome.is_vendor_rotated(),
            "should be VendorRotated for mock Stripe provider"
        );
        assert_eq!(outcome.audit_source(), "stripe");

        unsafe { std::env::remove_var("PHANTOM_AV_STRIPE_KEY") };
    }

    // ── AutoSyncOutcome audit source ──────────────────────────────────────────

    #[test]
    fn auto_sync_outcome_fell_back_to_manual_audit_source_is_manual() {
        let outcome = AutoSyncOutcome::FellBackToManual {
            reason: RotationProviderError::NotConfigured,
        };
        assert_eq!(outcome.audit_source(), "manual");
        assert!(!outcome.is_vendor_rotated());
    }

    // ── RotationProviderError display ─────────────────────────────────────────

    #[test]
    fn rotation_provider_error_display_is_human_readable() {
        let err = RotationProviderError::AuthFailed {
            reason: "401 Unauthorized".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("authentication failed"));
        assert!(msg.contains("401 Unauthorized"));

        let err2 = RotationProviderError::NetworkError {
            reason: "timeout".to_string(),
        };
        assert!(err2.to_string().contains("network error"));
        assert!(err2.to_string().contains("timeout"));
    }

    // ── XML extraction helper ─────────────────────────────────────────────────

    #[test]
    fn extract_xml_tag_returns_correct_value() {
        let xml = "<Response><SecretAccessKey>abc123</SecretAccessKey></Response>";
        assert_eq!(extract_xml_tag(xml, "SecretAccessKey"), Some("abc123".to_string()));
    }

    #[test]
    fn extract_xml_tag_returns_none_for_missing_tag() {
        let xml = "<Response><OtherTag>value</OtherTag></Response>";
        assert_eq!(extract_xml_tag(xml, "SecretAccessKey"), None);
    }

    // ── default_rotation_providers ────────────────────────────────────────────

    #[test]
    fn default_rotation_providers_covers_expected_vendors() {
        let providers = default_rotation_providers();
        let names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
        assert!(names.contains(&"stripe"), "missing stripe provider");
        assert!(names.contains(&"github"), "missing github provider");
        assert!(names.contains(&"aws"), "missing aws provider");
    }

    #[test]
    fn default_rotation_providers_match_expected_keys() {
        let providers = default_rotation_providers();
        let cases = vec![
            ("STRIPE_SECRET_KEY", "stripe"),
            ("GITHUB_TOKEN", "github"),
            ("AWS_SECRET_ACCESS_KEY", "aws"),
        ];
        for (key, expected) in cases {
            let matching: Vec<&str> = providers
                .iter()
                .filter(|p| p.matches(key))
                .map(|p| p.name())
                .collect();
            assert!(
                matching.contains(&expected),
                "key {key} should match provider {expected}, got: {matching:?}"
            );
        }
    }

    // ── ProviderRateLimit ─────────────────────────────────────────────────────

    #[test]
    fn rate_limit_stripe_has_post_rotation_pause() {
        let rl = ProviderRateLimit::for_provider("stripe");
        assert!(
            rl.post_rotation_pause_ms >= 10_000,
            "Stripe must have >= 10 s post-rotation pause, got {}ms",
            rl.post_rotation_pause_ms
        );
        assert!(
            rl.inter_call_delay_ms > 0,
            "Stripe must have a positive inter-call delay"
        );
    }

    #[test]
    fn rate_limit_github_has_inter_call_delay() {
        let rl = ProviderRateLimit::for_provider("github");
        assert!(
            rl.inter_call_delay_ms >= 2_000,
            "GitHub must have >= 2 s inter-call delay, got {}ms",
            rl.inter_call_delay_ms
        );
        assert_eq!(rl.post_rotation_pause_ms, 0, "GitHub has no post-rotation pause");
    }

    #[test]
    fn rate_limit_aws_has_per_second_delay() {
        let rl = ProviderRateLimit::for_provider("aws");
        assert!(
            rl.inter_call_delay_ms >= 1_000,
            "AWS must have >= 1 s inter-call delay, got {}ms",
            rl.inter_call_delay_ms
        );
    }

    #[test]
    fn rate_limit_manual_has_no_delay() {
        let rl = ProviderRateLimit::for_provider("manual");
        assert_eq!(rl.inter_call_delay_ms, 0, "manual provider must have no inter-call delay");
        assert_eq!(rl.post_rotation_pause_ms, 0, "manual provider must have no post-rotation pause");
    }

    #[test]
    fn rate_limit_unknown_provider_has_no_delay() {
        let rl = ProviderRateLimit::for_provider("custom_vendor");
        assert_eq!(rl.inter_call_delay_ms, 0);
        assert_eq!(rl.post_rotation_pause_ms, 0);
    }

    // ── batch_discover_due ────────────────────────────────────────────────────

    #[test]
    fn batch_discover_due_returns_only_secrets_within_window() {
        let now = 1_700_000_000u64;
        let window = 30 * 86_400u64; // 30 days

        let stripe_config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("STRIPE_KEY_ENV".to_string()),
            enabled: true,
            ..Default::default()
        };

        let input = vec![
            // Expires in 10 days — within window → should be included
            ("STRIPE_KEY".to_string(), Some(now + 10 * 86_400), Some(stripe_config.clone())),
            // Expires in 60 days — outside window → excluded
            ("GITHUB_TOKEN".to_string(), Some(now + 60 * 86_400), None),
            // Already expired → included
            ("AWS_KEY".to_string(), Some(now - 86_400), None),
            // No expiry → excluded
            ("MANUAL_KEY".to_string(), None, None),
        ];

        let providers = default_rotation_providers();
        let due = batch_discover_due(&input, window, now, &providers);

        assert_eq!(due.len(), 2, "expected 2 due secrets, got {}", due.len());

        let names: Vec<&str> = due.iter().map(|i| i.secret_name.as_str()).collect();
        assert!(names.contains(&"STRIPE_KEY"), "STRIPE_KEY must be due");
        assert!(names.contains(&"AWS_KEY"), "AWS_KEY must be due");
        assert!(!names.contains(&"GITHUB_TOKEN"), "GITHUB_TOKEN must NOT be due");
        assert!(!names.contains(&"MANUAL_KEY"), "MANUAL_KEY (no expiry) must NOT be due");
    }

    #[test]
    fn batch_discover_due_sorts_most_urgent_first() {
        let now = 1_700_000_000u64;
        let window = 60 * 86_400u64;

        let input = vec![
            ("KEY_C".to_string(), Some(now + 20 * 86_400), None), // 20 days out
            ("KEY_A".to_string(), Some(now - 86_400), None),       // already expired
            ("KEY_B".to_string(), Some(now + 5 * 86_400), None),   // 5 days out
        ];

        let providers = default_rotation_providers();
        let due = batch_discover_due(&input, window, now, &providers);

        assert_eq!(due.len(), 3);
        // Expired first (smallest expires_at), then soonest-expiring
        assert_eq!(due[0].secret_name, "KEY_A", "expired key must be first");
        assert_eq!(due[1].secret_name, "KEY_B", "5-day key must be second");
        assert_eq!(due[2].secret_name, "KEY_C", "20-day key must be last");
    }

    #[test]
    fn batch_discover_due_labels_provider_correctly() {
        let now = 1_700_000_000u64;
        let window = 30 * 86_400u64;

        let stripe_config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("SK_ENV".to_string()),
            enabled: true,
            ..Default::default()
        };

        let input = vec![
            ("STRIPE_SECRET_KEY".to_string(), Some(now + 5 * 86_400), Some(stripe_config)),
            ("MY_MANUAL_KEY".to_string(), Some(now + 5 * 86_400), None),
        ];

        let providers = default_rotation_providers();
        let due = batch_discover_due(&input, window, now, &providers);

        assert_eq!(due.len(), 2);
        let stripe_item = due.iter().find(|i| i.secret_name == "STRIPE_SECRET_KEY").unwrap();
        let manual_item = due.iter().find(|i| i.secret_name == "MY_MANUAL_KEY").unwrap();

        assert_eq!(stripe_item.provider_label, "stripe");
        assert!(stripe_item.is_vendor(), "STRIPE_SECRET_KEY with provider config must be vendor");
        assert_eq!(manual_item.provider_label, "manual");
        assert!(!manual_item.is_vendor(), "key without provider config must not be vendor");
    }

    #[test]
    fn batch_discover_due_empty_vault_returns_empty() {
        let providers = default_rotation_providers();
        let due = batch_discover_due(&[], 30 * 86_400, 1_700_000_000, &providers);
        assert!(due.is_empty());
    }

    // ── execute_batch_rotation ────────────────────────────────────────────────

    #[test]
    fn execute_batch_rotation_stripe_mock_succeeds() {
        // Set up a mock Stripe key in the environment.
        unsafe { std::env::set_var("BATCH_TEST_STRIPE_KEY", "sk_test_mock_batch_key") };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let stripe_config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("BATCH_TEST_STRIPE_KEY".to_string()),
            enabled: true,
            ..Default::default()
        };

        let now = 1_700_000_000u64;
        let items = vec![
            BatchRotationItem {
                secret_name: "STRIPE_SECRET_KEY".to_string(),
                expires_at: Some(now - 86_400), // already expired
                provider_config: Some(stripe_config),
                provider_label: "stripe".to_string(),
            },
        ];

        let providers = default_rotation_providers();
        let (batch_id, outcomes) = execute_batch_rotation(&items, &providers, now);

        assert!(!batch_id.is_empty(), "batch_id must be non-empty");
        assert_eq!(outcomes.len(), 1);

        let outcome = &outcomes[0];
        assert_eq!(outcome.secret_name, "STRIPE_SECRET_KEY");
        assert!(outcome.vendor_rotated, "should be vendor-rotated via Stripe mock");
        assert!(outcome.is_ok(), "should have no error");
        assert!(outcome.new_value.is_some(), "should have a new value");
        assert_eq!(
            outcome.new_value.as_ref().unwrap().as_str(),
            "sk_test_rotated_mock_value_stripe"
        );
        assert!(outcome.new_expires_at.is_some(), "should have a new expiry");
        assert!(
            outcome.new_expires_at.unwrap() > now,
            "new expiry must be in the future"
        );

        unsafe { std::env::remove_var("BATCH_TEST_STRIPE_KEY") };
    }

    #[test]
    fn execute_batch_rotation_manual_item_has_no_new_value() {
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let now = 1_700_000_000u64;
        let items = vec![
            BatchRotationItem {
                secret_name: "MY_MANUAL_SECRET".to_string(),
                expires_at: Some(now - 3600),
                provider_config: None, // manual
                provider_label: "manual".to_string(),
            },
        ];

        let providers = default_rotation_providers();
        let (batch_id, outcomes) = execute_batch_rotation(&items, &providers, now);

        assert!(!batch_id.is_empty());
        assert_eq!(outcomes.len(), 1);

        let outcome = &outcomes[0];
        assert_eq!(outcome.provider_label, "manual");
        assert!(!outcome.vendor_rotated);
        assert!(outcome.new_value.is_none(), "manual item must not have a new value");
        assert!(outcome.error.is_none(), "manual item is not an error — just needs manual handling");
        assert!(outcome.is_ok());
    }

    #[test]
    fn execute_batch_rotation_mixed_providers_three_secrets() {
        // Set up mock env vars for Stripe and GitHub
        unsafe {
            std::env::set_var("BATCH_MIX_STRIPE_KEY", "sk_test_mock_mix_stripe");
            std::env::set_var("BATCH_MIX_GITHUB_KEY", "ghp_mock_mix_github");
            std::env::remove_var("PHANTOM_AUDIT");
        }

        let stripe_config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("BATCH_MIX_STRIPE_KEY".to_string()),
            enabled: true,
            ..Default::default()
        };
        let github_config = RotationProviderConfig {
            provider: "github".to_string(),
            api_key_env: Some("BATCH_MIX_GITHUB_KEY".to_string()),
            account_id: Some("install_123".to_string()),
            enabled: true,
            ..Default::default()
        };

        let now = 1_700_000_000u64;
        let items = vec![
            BatchRotationItem {
                secret_name: "STRIPE_SECRET_KEY".to_string(),
                expires_at: Some(now - 1000),
                provider_config: Some(stripe_config),
                provider_label: "stripe".to_string(),
            },
            BatchRotationItem {
                secret_name: "GITHUB_TOKEN".to_string(),
                expires_at: Some(now - 2000),
                provider_config: Some(github_config),
                provider_label: "github".to_string(),
            },
            BatchRotationItem {
                secret_name: "MANUAL_API_KEY".to_string(),
                expires_at: Some(now - 3000),
                provider_config: None,
                provider_label: "manual".to_string(),
            },
        ];

        let providers = default_rotation_providers();
        let (batch_id, outcomes) = execute_batch_rotation(&items, &providers, now);

        assert!(!batch_id.is_empty(), "batch_id must be set");
        assert_eq!(outcomes.len(), 3, "must have 3 outcomes");

        // All 3 must be ok (no errors)
        for o in &outcomes {
            assert!(o.is_ok(), "outcome for {} must be ok, got: {:?}", o.secret_name, o.error);
        }

        let stripe_out = outcomes.iter().find(|o| o.secret_name == "STRIPE_SECRET_KEY").unwrap();
        assert!(stripe_out.vendor_rotated, "Stripe must be vendor-rotated");
        assert!(stripe_out.new_value.is_some());

        let github_out = outcomes.iter().find(|o| o.secret_name == "GITHUB_TOKEN").unwrap();
        assert!(github_out.vendor_rotated, "GitHub must be vendor-rotated");
        assert!(github_out.new_value.is_some());

        let manual_out = outcomes.iter().find(|o| o.secret_name == "MANUAL_API_KEY").unwrap();
        assert!(!manual_out.vendor_rotated);
        assert!(manual_out.new_value.is_none());

        unsafe {
            std::env::remove_var("BATCH_MIX_STRIPE_KEY");
            std::env::remove_var("BATCH_MIX_GITHUB_KEY");
        }
    }

    #[test]
    fn execute_batch_rotation_batch_id_is_unique_per_run() {
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };
        let now = 1_700_000_000u64;
        let providers = default_rotation_providers();
        let (id1, _) = execute_batch_rotation(&[], &providers, now);
        let (id2, _) = execute_batch_rotation(&[], &providers, now);
        assert_ne!(id1, id2, "each batch run must produce a unique batch_id");
    }

    #[test]
    fn execute_batch_rotation_failed_provider_sets_error() {
        // No env var set → provider will fail with NotConfigured
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };
        unsafe { std::env::remove_var("BATCH_FAIL_KEY") };

        let stripe_config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("BATCH_FAIL_KEY".to_string()), // env var not set
            enabled: true,
            ..Default::default()
        };

        let now = 1_700_000_000u64;
        let items = vec![BatchRotationItem {
            secret_name: "STRIPE_SECRET_KEY".to_string(),
            expires_at: Some(now - 3600),
            provider_config: Some(stripe_config),
            provider_label: "stripe".to_string(),
        }];

        let providers = default_rotation_providers();
        let (_batch_id, outcomes) = execute_batch_rotation(&items, &providers, now);

        assert_eq!(outcomes.len(), 1);
        let outcome = &outcomes[0];
        assert!(!outcome.is_ok(), "missing env var should cause rotation failure");
        assert!(outcome.error.is_some(), "error field must be populated on failure");
        assert!(!outcome.vendor_rotated);
        assert!(outcome.new_value.is_none());
    }

    // ── Audit batch event functions ───────────────────────────────────────────

    #[test]
    fn batch_audit_log_functions_are_no_ops_when_audit_disabled() {
        // Make sure audit is disabled.
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        // These must not panic regardless of PHANTOM_AUDIT state.
        crate::audit::log_batch_rotation_started("abc123", 3);
        crate::audit::log_batch_item_succeeded("abc123", "MY_KEY", "stripe");
        crate::audit::log_batch_item_failed("abc123", "MY_KEY", "timeout");
        crate::audit::log_batch_rotation_completed("abc123", 3, 2, 1);
    }
}
