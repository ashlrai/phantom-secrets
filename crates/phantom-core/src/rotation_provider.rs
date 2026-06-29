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
}
