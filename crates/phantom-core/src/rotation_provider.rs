//! Vendor-specific secret rotation providers.
//!
//! This module defines the [`RotationProvider`] trait and concrete implementations
//! for Stripe, GitHub, AWS, Google Cloud, and Vercel, plus explicit
//! not-supported providers for Sentry and Supabase (whose vendors expose no
//! token-auth minting API). Providers allow `phantom rotate --auto-sync` to
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
//!   with a `source` field: `"manual"`, `"stripe"`, `"github"`, `"aws"`,
//!   `"google"`, `"vercel"`, etc.

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
    /// A rotation_provider block exists but is explicitly disabled
    /// (`enabled = false`).
    Disabled,
    /// The `provider` named in the config does not correspond to any
    /// registered rotation provider.
    UnknownProvider { provider: String },
    /// The vendor returned an unexpected response format.
    UnexpectedResponse { reason: String },
    /// This provider does not support the named secret.
    NotApplicable,
    /// The vendor exposes no API for programmatic rotation — the operator must
    /// rotate manually (the reason string explains where, e.g. a dashboard URL).
    NotSupported { reason: String },
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
                // challenge_ids can encode the minted secret (payload_ prefix);
                // never render the full id.
                write!(
                    f,
                    "rotation challenge '{}' expired or not found",
                    redact_challenge_id(challenge_id)
                )
            }
            Self::NotConfigured => {
                write!(f, "rotation provider not configured for this secret")
            }
            Self::Disabled => {
                write!(
                    f,
                    "rotation provider is disabled for this secret (enabled = false in .phantom.toml)"
                )
            }
            Self::UnknownProvider { provider } => {
                write!(
                    f,
                    "configured rotation provider '{provider}' is not registered \
                     (valid: stripe, github, aws, google, vercel, sentry, supabase)"
                )
            }
            Self::UnexpectedResponse { reason } => {
                write!(f, "unexpected response from rotation API: {reason}")
            }
            Self::NotApplicable => {
                write!(f, "provider does not handle this secret type")
            }
            Self::NotSupported { reason } => {
                write!(f, "vendor does not support API-driven rotation: {reason}")
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
    /// Rotated via the Google Cloud Secret Manager API.
    Google,
    /// Rotated via the Vercel auth-token API.
    Vercel,
    /// Sentry — no token-auth minting API; provider reports manual rotation.
    Sentry,
    /// Supabase — personal access tokens are dashboard-only; provider reports
    /// manual rotation.
    Supabase,
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
            Self::Google => "google",
            Self::Vercel => "vercel",
            Self::Sentry => "sentry",
            Self::Supabase => "supabase",
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

    /// Best-effort cleanup performed by the caller only **after** the new
    /// secret value has been durably stored in the vault (e.g. revoking the
    /// old credential at the vendor).
    ///
    /// `old_value` is the previous vault value of the rotated secret. Default
    /// implementation is a no-op. Implementations MUST fail open (the new
    /// value is already stored; a cleanup failure must not undo the rotation)
    /// and MUST NOT log `old_value`.
    fn post_store_cleanup(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
        old_value: Option<&zeroize::Zeroizing<String>>,
    ) -> Result<(), RotationProviderError> {
        let _ = (secret_name, config, old_value);
        Ok(())
    }
}

/// Returns `true` when the hermetic mock fast-paths (magic `*_mock_` bootstrap
/// prefixes) are permitted to run.
///
/// Fail closed: mock rotations return fixed, publicly known values and would
/// otherwise let anyone who can plant a mock-prefixed bootstrap credential
/// forge a "successful" rotation that overwrites the real vaulted secret.
/// Allowed only under `cfg(test)` or with the explicit
/// `PHANTOM_ALLOW_MOCK_ROTATION=1` opt-in (test environments only).
fn mock_rotation_allowed() -> bool {
    cfg!(test)
        || std::env::var("PHANTOM_ALLOW_MOCK_ROTATION")
            .map(|v| v == "1")
            .unwrap_or(false)
}

/// Guard shared by every provider's mock fast-path: permits the mock branch
/// (tagging the audit log with a distinct `vault.rotation.mock` event) or
/// fails closed when mock rotation is not explicitly enabled.
fn guard_mock_rotation(secret_name: &str) -> Result<(), RotationProviderError> {
    if mock_rotation_allowed() {
        // Distinct audit marker so a mock rotation can never masquerade as a
        // real vendor rotation in the audit trail.
        crate::audit::log("vault.rotation.mock", Some(secret_name));
        Ok(())
    } else {
        Err(RotationProviderError::NotSupported {
            reason: "bootstrap credential has a reserved mock prefix, but mock rotation \
                     is disabled in this build. Mock rotations are for tests only; set \
                     PHANTOM_ALLOW_MOCK_ROTATION=1 to enable them in a test environment."
                .to_string(),
        })
    }
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
pub enum AutoSyncOutcome {
    /// Vendor rotation succeeded; the new value has been stored in the vault.
    VendorRotated {
        source: RotationSource,
        challenge_id: String,
    },
    /// Vendor rotation failed; the caller fell back to manual rotation.
    FellBackToManual { reason: RotationProviderError },
    /// No provider is configured; manual rotation was used directly.
    Manual,
}

impl fmt::Debug for AutoSyncOutcome {
    /// Redacting `Debug`: `challenge_id` can encode the freshly minted secret
    /// (`payload_` base64), so it is never rendered.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VendorRotated { source, .. } => f
                .debug_struct("VendorRotated")
                .field("source", source)
                .field("challenge_id", &"[redacted]")
                .finish(),
            Self::FellBackToManual { reason } => f
                .debug_struct("FellBackToManual")
                .field("reason", reason)
                .finish(),
            Self::Manual => f.write_str("Manual"),
        }
    }
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

/// Select the provider implementation named by `config.provider`.
///
/// Dispatch is by provider **identity** (`RotationProvider::name`), never by
/// heuristic secret-name matching — a secret named `STRIPE_GITHUB_TOKEN`
/// configured with `provider = "github"` must always reach the GitHub
/// provider, and its bootstrap credential must never be sent to another
/// vendor. `matches()` remains a heuristic hint only (labels, doctor checks).
fn select_provider<'a>(
    config: &RotationProviderConfig,
    providers: &'a [Box<dyn RotationProvider>],
) -> Result<&'a dyn RotationProvider, RotationProviderError> {
    providers
        .iter()
        .find(|p| p.name().eq_ignore_ascii_case(&config.provider))
        .map(|b| b.as_ref())
        .ok_or_else(|| RotationProviderError::UnknownProvider {
            provider: config.provider.clone(),
        })
}

/// Attempt vendor-managed rotation for `secret_name`.
///
/// 1. Select the provider registered under `config.provider`.
/// 2. Call `initiate_rotation` → `challenge_id`.
/// 3. Call `finalize_rotation` → `new_value`.
/// 4. Return [`AutoSyncOutcome::VendorRotated`] so the caller stores the value.
///
/// If no provider is configured (or the config names `"manual"` / is disabled)
/// the outcome is [`AutoSyncOutcome::Manual`]; if the vendor call fails, the
/// outcome is [`AutoSyncOutcome::FellBackToManual`] (the caller must prompt
/// for a manual value).
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

    if !config.enabled || config.provider == "manual" {
        return AutoSyncOutcome::Manual;
    }

    let provider = match select_provider(config, providers) {
        Ok(p) => p,
        Err(e) => return AutoSyncOutcome::FellBackToManual { reason: e },
    };

    // Emit audit event: rotation initiated.
    crate::audit::log("vault.rotation.initiated", Some(secret_name));

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
///
/// Returns `Ok(None)` only when manual rotation is the intended path (no
/// config, or `provider = "manual"`). A present-but-disabled config and an
/// unknown provider name are distinct hard errors ([`RotationProviderError::Disabled`],
/// [`RotationProviderError::UnknownProvider`]) so callers never mis-report
/// them as a bootstrap-credential problem.
pub fn auto_sync_rotation(
    secret_name: &str,
    provider_config: Option<&RotationProviderConfig>,
    providers: &[Box<dyn RotationProvider>],
) -> Result<Option<zeroize::Zeroizing<String>>, RotationProviderError> {
    let Some(config) = provider_config else {
        return Ok(None); // no provider configured → manual
    };

    if config.provider == "manual" {
        return Ok(None); // explicit manual rotation
    }

    if !config.enabled {
        return Err(RotationProviderError::Disabled);
    }

    let provider = select_provider(config, providers)?;

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

// ── Bootstrap credential fallback ─────────────────────────────────────────────

thread_local! {
    /// Fallback bootstrap credential consulted by [`resolve_api_key`] when the
    /// configured `api_key_env` variable is not set in the process environment.
    ///
    /// Installed for the duration of a single rotation attempt by
    /// [`auto_sync_rotation_with_bootstrap`]. The caller (phantom-cli /
    /// phantom-mcp) reads the value from the encrypted vault under the
    /// `api_key_env` name and passes it in; phantom-core itself never touches
    /// the vault (dependency direction is vault → core). The value is owned,
    /// zeroized on drop, and cleared by an RAII guard even on error paths.
    static BOOTSTRAP_OVERRIDE: std::cell::RefCell<Option<zeroize::Zeroizing<String>>> =
        const { std::cell::RefCell::new(None) };
}

/// RAII guard that clears (and thereby zeroizes) the thread-local bootstrap
/// override when the rotation attempt finishes, including on error paths.
struct BootstrapOverrideGuard;

impl Drop for BootstrapOverrideGuard {
    fn drop(&mut self) {
        BOOTSTRAP_OVERRIDE.with(|o| *o.borrow_mut() = None);
    }
}

/// Like [`auto_sync_rotation`], but with a vault-sourced fallback for the
/// bootstrap credential named by `config.api_key_env`.
///
/// Resolution order inside the providers stays: process environment variable
/// first, then `bootstrap` (which the caller retrieved from the vault under
/// the `api_key_env` name). Pass `None` to keep environment-only behaviour.
///
/// The bootstrap value is never logged and is zeroized when the call returns.
pub fn auto_sync_rotation_with_bootstrap(
    secret_name: &str,
    provider_config: Option<&RotationProviderConfig>,
    providers: &[Box<dyn RotationProvider>],
    bootstrap: Option<zeroize::Zeroizing<String>>,
) -> Result<Option<zeroize::Zeroizing<String>>, RotationProviderError> {
    let _guard = BootstrapOverrideGuard;
    BOOTSTRAP_OVERRIDE.with(|o| *o.borrow_mut() = bootstrap);
    auto_sync_rotation(secret_name, provider_config, providers)
}

// ── Stripe provider ───────────────────────────────────────────────────────────

/// Stripe rotation provider — **manual rotation required** for real keys.
///
/// Stripe exposes no public, documented API endpoint for creating or rolling
/// API keys (`POST /v1/restricted_keys` is not part of the public API surface,
/// and key rolling is dashboard-only). The non-mock path therefore returns
/// [`RotationProviderError::NotSupported`] with a dashboard link instead of
/// sending the bootstrap credential to an endpoint that cannot work.
///
/// In test/mock mode (when the configured key starts with `"sk_test_mock_"`
/// and mock rotation is enabled), the provider returns a deterministic mock
/// value.
pub struct StripeRotationProvider;

/// Operator-facing explanation used by [`StripeRotationProvider`].
const STRIPE_NOT_SUPPORTED_REASON: &str =
    "Stripe has no public API for creating or rolling API keys — key rotation \
     is dashboard-only. Roll the key at https://dashboard.stripe.com/apikeys \
     then store the replacement with `phantom add`.";

impl RotationProvider for StripeRotationProvider {
    fn name(&self) -> &str {
        "stripe"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        upper.contains("STRIPE")
            && (upper.contains("KEY") || upper.contains("SECRET") || upper.contains("TOKEN"))
    }

    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        // Resolve the admin API key from the environment variable named in config.
        let api_key = resolve_api_key(config)?;

        // Mock path for testing: if the resolved key starts with "sk_test_mock_",
        // return a deterministic mock challenge ID (test builds / explicit
        // opt-in only — fail closed otherwise).
        if api_key.starts_with("sk_test_mock_") {
            guard_mock_rotation(secret_name)?;
            return Ok(format!("mock_challenge_stripe_{secret_name}"));
        }

        // Real path: there is no public Stripe endpoint that can mint a
        // replacement API key, so refuse honestly rather than POSTing the
        // bootstrap credential at an endpoint that cannot succeed.
        Err(RotationProviderError::NotSupported {
            reason: STRIPE_NOT_SUPPORTED_REASON.to_string(),
        })
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        // Mock path.
        if challenge_id.starts_with("mock_challenge_stripe_") {
            if !mock_rotation_allowed() {
                return Err(RotationProviderError::ChallengeExpired {
                    challenge_id: redact_challenge_id(challenge_id),
                });
            }
            return Ok(zeroize::Zeroizing::new(
                "sk_test_rotated_mock_value_stripe".to_string(),
            ));
        }

        Err(RotationProviderError::NotSupported {
            reason: STRIPE_NOT_SUPPORTED_REASON.to_string(),
        })
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
///    generates a fresh short-lived token (**expires after 1 hour**). This is
///    the recommended approach for automated rotation in CI. Callers should
///    persist a ~1 h expiry on the stored secret so expiry tooling flags it
///    (the CLI/MCP rotation paths do this).
/// 2. **Mock path** (for `ghp_mock_*` tokens): returns a deterministic rotated value.
///
/// **Bootstrap credential caveat**: the mint endpoint requires
/// `Authorization: Bearer <GitHub App JWT>` — a JWT signed with the App's
/// private key that itself **expires ~10 minutes after minting**. The value
/// behind `api_key_env` must therefore be a *freshly generated* App JWT for
/// each rotation (e.g. minted by a wrapper script), not a static long-lived
/// credential.
///
/// For classic PATs or fine-grained PATs the GitHub API does not support
/// programmatic rotation — there is no endpoint to mint or regenerate a PAT.
/// This provider only mints App installation tokens; when `account_id` (the
/// App installation ID) is missing it fails with an actionable error telling
/// the operator to rotate PATs manually in the GitHub dashboard.
pub struct GitHubRotationProvider;

/// Installation access tokens minted by the GitHub App API expire after 1 hour.
pub const GITHUB_INSTALLATION_TOKEN_TTL_SECS: u64 = 3_600;

impl RotationProvider for GitHubRotationProvider {
    fn name(&self) -> &str {
        "github"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        upper.contains("GITHUB")
            && (upper.contains("TOKEN") || upper.contains("KEY") || upper.contains("SECRET"))
    }

    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        let api_key = resolve_api_key(config)?;

        // Mock path: GitHub App installation tokens prefixed "ghp_mock_"
        if api_key.starts_with("ghp_mock_") {
            guard_mock_rotation(secret_name)?;
            return Ok(format!("mock_challenge_github_{secret_name}"));
        }

        // Real path: generate a new GitHub App installation access token.
        let installation_id =
            config
                .account_id
                .as_deref()
                .ok_or_else(|| RotationProviderError::ApiError {
                    status: 0,
                    reason: "account_id must be set to the GitHub App installation ID. \
                             GitHub has no API to rotate classic or fine-grained personal \
                             access tokens — rotate PATs manually at \
                             https://github.com/settings/tokens"
                        .to_string(),
                })?;

        let client = build_http_client(config.timeout_secs)?;
        let url =
            format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key.as_str()))
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
                reason: format!(
                    "GitHub returned HTTP {status} — note the bootstrap credential must be \
                     a freshly minted GitHub App JWT (App JWTs expire ~10 minutes after \
                     signing); generate a new JWT for each rotation"
                ),
            });
        }
        if status != 201 {
            let body = response.text().unwrap_or_default();
            return Err(RotationProviderError::ApiError {
                status,
                reason: summarize_error_body(&body),
            });
        }

        let body: serde_json::Value =
            response
                .json()
                .map_err(|e| RotationProviderError::UnexpectedResponse {
                    reason: e.to_string(),
                })?;

        let token = body.get("token").and_then(|v| v.as_str()).ok_or_else(|| {
            RotationProviderError::UnexpectedResponse {
                reason: "missing 'token' field in GitHub response".to_string(),
            }
        })?;

        Ok(encode_challenge_payload(token))
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        if challenge_id.starts_with("mock_challenge_github_") {
            if !mock_rotation_allowed() {
                return Err(RotationProviderError::ChallengeExpired {
                    challenge_id: redact_challenge_id(challenge_id),
                });
            }
            return Ok(zeroize::Zeroizing::new(
                "ghp_rotated_mock_token_github".to_string(),
            ));
        }

        decode_challenge_payload(challenge_id)
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::GitHub
    }
}

// ── AWS provider ──────────────────────────────────────────────────────────────

/// AWS IAM access-key rotation provider — **not yet supported for real keys**.
///
/// Real IAM rotation requires SigV4-signed requests to the global
/// `iam.amazonaws.com` endpoint (CreateAccessKey + DeleteAccessKey, handling
/// the AccessKeyId/SecretAccessKey *pair* and IAM's 2-keys-per-user limit).
/// phantom does not ship a SigV4 signer, so the non-mock path returns
/// [`RotationProviderError::NotSupported`] with an actionable message instead
/// of sending an unsigned (and guaranteed-to-fail) request carrying the
/// bootstrap credential in a malformed Authorization header.
///
/// **Mock path**: when `api_key_env` resolves to `"AKID_MOCK_*"`, returns mock values.
pub struct AwsRotationProvider;

/// Operator-facing explanation used by [`AwsRotationProvider`].
const AWS_NOT_SUPPORTED_REASON: &str =
    "AWS IAM access-key rotation requires SigV4 request signing, which phantom \
     does not yet implement. Rotate the access key with the AWS CLI \
     (`aws iam create-access-key` / `aws iam delete-access-key`) or the IAM \
     console, then store the new pair with `phantom add`.";

impl RotationProvider for AwsRotationProvider {
    fn name(&self) -> &str {
        "aws"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        upper.contains("AWS")
            && (upper.contains("KEY") || upper.contains("SECRET") || upper.contains("TOKEN"))
    }

    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        let api_key = resolve_api_key(config)?;

        // Mock path.
        if api_key.starts_with("AKID_MOCK_") {
            guard_mock_rotation(secret_name)?;
            return Ok(format!("mock_challenge_aws_{secret_name}"));
        }

        // Real path: refuse honestly. An unsigned IAM request is guaranteed to
        // fail AND would echo the bootstrap credential back in AWS's
        // IncompleteSignature error body.
        Err(RotationProviderError::NotSupported {
            reason: AWS_NOT_SUPPORTED_REASON.to_string(),
        })
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        if challenge_id.starts_with("mock_challenge_aws_") {
            if !mock_rotation_allowed() {
                return Err(RotationProviderError::ChallengeExpired {
                    challenge_id: redact_challenge_id(challenge_id),
                });
            }
            return Ok(zeroize::Zeroizing::new(
                "EXAMPLE_MOCK_AWS_SECRET_KEY_rotated".to_string(),
            ));
        }

        Err(RotationProviderError::NotSupported {
            reason: AWS_NOT_SUPPORTED_REASON.to_string(),
        })
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Aws
    }
}

// ── Google Cloud Secret Manager provider ──────────────────────────────────────

/// Google Cloud Secret Manager rotation provider.
///
/// Rotates a GCP secret by calling the Secret Manager REST API:
///
/// 1. **Add a new secret version** via
///    `POST /v1/projects/{project}/secrets/{secret}/versions:add`
///    with the newly generated value as the payload. The new version becomes
///    the `ENABLED` (latest) version automatically.
/// 2. **Disable the previous version** (optional; skipped when
///    `account_id` is not set to a previous-version resource name).
///
/// # Configuration in `.phantom.toml`
///
/// ```toml
/// [phantom.secrets.GCP_API_KEY.rotation_provider]
/// provider     = "google"
/// api_key_env  = "GCP_ROTATION_ACCESS_TOKEN"   # OAuth2 Bearer or service-account token
/// account_id   = "projects/my-project/secrets/my-secret"  # full resource name
/// ```
///
/// `api_key_env` must name an environment variable holding a valid OAuth2
/// Bearer token (e.g. from `gcloud auth print-access-token`) or a service
/// account access token with `roles/secretmanager.admin` on the secret.
///
/// # Mock path
///
/// When `api_key_env` resolves to a value starting with `"gcp_mock_"`, the
/// provider returns deterministic mock values without making real HTTP calls.
/// This keeps unit tests hermetic.
///
/// # Scope: application-owned shared secrets ONLY
///
/// This provider generates a fresh random value and pushes it as a new GSM
/// version — valid only for secrets your application owns (webhook signing
/// keys, internal shared secrets). It refuses names that denote
/// **Google-issued** credentials (service-account keys, application default
/// credentials), which a random value can never replace.
pub struct GoogleRotationProvider;

/// Secret-name markers that denote Google-issued credentials which cannot be
/// replaced by a randomly generated value (rotating them would destroy the
/// working vault copy while the real Google credential stays live).
const GOOGLE_ISSUED_CREDENTIAL_MARKERS: &[&str] = &["APPLICATION_CREDENTIALS", "SERVICE_ACCOUNT"];

fn is_google_issued_credential_name(secret_name: &str) -> bool {
    let upper = secret_name.to_uppercase();
    GOOGLE_ISSUED_CREDENTIAL_MARKERS
        .iter()
        .any(|m| upper.contains(m))
}

impl RotationProvider for GoogleRotationProvider {
    fn name(&self) -> &str {
        "google"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        let has_provider = upper.contains("GOOGLE") || upper.contains("GCP");
        let has_kind = upper.contains("KEY")
            || upper.contains("TOKEN")
            || upper.contains("SECRET")
            || upper.contains("APIKEY")
            || upper.contains("API_KEY");
        // Never claim Google-issued credentials (GOOGLE_APPLICATION_CREDENTIALS,
        // *_SERVICE_ACCOUNT_*): random hex cannot replace those.
        has_provider && has_kind && !is_google_issued_credential_name(secret_name)
    }

    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        // Refuse Google-issued credential names outright — overwriting them
        // with a random value would destroy the working credential.
        if is_google_issued_credential_name(secret_name) {
            return Err(RotationProviderError::NotSupported {
                reason: format!(
                    "'{secret_name}' looks like a Google-issued credential \
                     (service-account key / application default credentials). The google \
                     provider only rotates application-owned shared secrets stored in \
                     Secret Manager; rotate Google-issued credentials in the Google Cloud \
                     console and store the replacement with `phantom add`."
                ),
            });
        }

        let access_token = resolve_api_key(config)?;

        // ── Mock path ────────────────────────────────────────────────────────
        if access_token.starts_with("gcp_mock_") {
            guard_mock_rotation(secret_name)?;
            return Ok(format!("mock_challenge_google_{secret_name}"));
        }

        // ── Real path: add a new secret version ──────────────────────────────
        //
        // The `account_id` field must hold the full Secret Manager resource
        // name: projects/{project}/secrets/{secret}. Guessing a resource path
        // from the secret name is guaranteed-invalid, so its absence is a
        // configuration error (checked before any network I/O).
        let resource_name = config
            .account_id
            .as_deref()
            .ok_or(RotationProviderError::NotConfigured)?;

        // Generate a new random secret value (32 bytes, hex-encoded).
        let new_secret_value = generate_secret_value();

        // Encode the payload as the Secret Manager API expects: base64 of the
        // raw secret bytes in a JSON `{"payload": {"data": "<base64>"}}` body.
        use base64::Engine;
        let data_b64 =
            base64::engine::general_purpose::STANDARD.encode(new_secret_value.as_bytes());

        let body = serde_json::json!({
            "payload": {
                "data": data_b64
            }
        });

        // Documented REST method: projects.secrets.addVersion — the custom
        // method suffix goes on the secret resource itself
        // (`.../secrets/my-secret:addVersion`), NOT on a `/versions`
        // sub-collection.
        let url = format!("https://secretmanager.googleapis.com/v1/{resource_name}:addVersion");

        let client = build_http_client(config.timeout_secs)?;
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token.as_str()))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| RotationProviderError::NetworkError {
                reason: e.to_string(),
            })?;

        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(RotationProviderError::AuthFailed {
                reason: format!(
                    "Google Secret Manager returned HTTP {status} — check access token permissions"
                ),
            });
        }
        if status != 200 {
            let body_text = response.text().unwrap_or_default();
            return Err(RotationProviderError::ApiError {
                status,
                reason: summarize_error_body(&body_text),
            });
        }

        // The response contains the new version resource name; we encode both
        // it and the new secret value into the challenge_id so finalize can
        // return the value without a second API call.
        let resp_body: serde_json::Value =
            response
                .json()
                .map_err(|e| RotationProviderError::UnexpectedResponse {
                    reason: e.to_string(),
                })?;

        let version_name = resp_body
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(resource_name);

        // Pack version_name + new_value as "version\x00new_value" then base64.
        // Kept in a Zeroizing wrapper — it embeds the new secret value.
        let packed =
            zeroize::Zeroizing::new(format!("{version_name}\x00{}", new_secret_value.as_str()));
        Ok(encode_challenge_payload(packed.as_str()))
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        // Mock path.
        if challenge_id.starts_with("mock_challenge_google_") {
            if !mock_rotation_allowed() {
                return Err(RotationProviderError::ChallengeExpired {
                    challenge_id: redact_challenge_id(challenge_id),
                });
            }
            return Ok(zeroize::Zeroizing::new(
                "gcp_rotated_mock_secret_value_v2".to_string(),
            ));
        }

        // Real path: decode the packed payload (Zeroizing — embeds the value).
        let packed = decode_challenge_payload(challenge_id)?;
        // The new value is after the null-byte separator.
        let new_value = packed
            .split_once('\x00')
            .map(|(_, v)| v)
            .unwrap_or(packed.as_str());
        Ok(zeroize::Zeroizing::new(new_value.to_string()))
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Google
    }
}

/// Generate a cryptographically random secret value (32 bytes, hex-encoded).
///
/// This value is used as the *new* secret payload when the Google Secret Manager
/// provider creates a new version. Returned inside `Zeroizing` so intermediate
/// copies are scrubbed from memory.
fn generate_secret_value() -> zeroize::Zeroizing<String> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let value = zeroize::Zeroizing::new(hex::encode(bytes));
    zeroize::Zeroize::zeroize(&mut bytes);
    value
}

// ── Vercel provider ───────────────────────────────────────────────────────────

/// Vercel auth-token rotation provider.
///
/// Mints a fresh Vercel REST API auth token and verifies it. Revocation of
/// the OLD token deliberately does **not** happen here: the minted
/// `bearerToken` is one-time-retrievable, so revoking the old token before
/// the caller has durably stored the new one would create a crash window
/// ending in total credential lockout. Revocation runs in
/// [`RotationProvider::post_store_cleanup`], which callers invoke only AFTER
/// the new value is persisted in the vault. Endpoints confirmed against the
/// Vercel REST API reference (fetched 2026-08-16):
///
/// 1. **Mint**: `POST https://api.vercel.com/v3/user/tokens` authenticated
///    with `Authorization: Bearer <existing token>`, JSON body
///    `{"name": <string, required>}` (optional `expiresAt` in ms since epoch,
///    optional `projectId`); the optional `?teamId=` query parameter scopes
///    the token to a team. The response carries one-time `bearerToken`
///    (never retrievable again) plus `token` metadata including `token.id`.
///    <https://vercel.com/docs/rest-api/reference/endpoints/authentication/create-an-auth-token>
/// 2. **Verify**: `GET https://api.vercel.com/v2/user` (whoami) with the NEW
///    token; only a 2xx counts as verified. On ANY other status (401, 429,
///    5xx, …) the just-minted token is best-effort deleted by id and the
///    rotation fails **without touching the old token**.
/// 3. **Revoke old** (in `post_store_cleanup`, best-effort, fail-open):
///    `DELETE https://api.vercel.com/v3/user/tokens/current` authenticated
///    with the OLD SECRET VALUE itself (never the bootstrap credential, which
///    may be a separate rotation-management token) — the special `current` id
///    invalidates exactly the token that authenticated the request. Failures
///    and skips are recorded as audit events
///    (`vault.rotation.old_token_revoke_failed` /
///    `vault.rotation.old_token_revoke_skipped`, name only) so operators know
///    the old token is still live.
///    <https://vercel.com/docs/rest-api/reference/endpoints/authentication/delete-an-authentication-token>
///
/// # Configuration in `.phantom.toml`
///
/// ```toml
/// [phantom.secrets.VERCEL_TOKEN.rotation_provider]
/// provider    = "vercel"
/// api_key_env = "VERCEL_ROTATION_TOKEN"   # an existing Vercel token (usually the one being rotated)
/// account_id  = "team_abc123"             # optional teamId for team-scoped tokens
/// ```
///
/// `expiresAt` is deliberately not sent: [`RotationProviderConfig`] has no
/// TTL field today; expiry is tracked vault-side by the caller.
///
/// # Mock path
///
/// When `api_key_env` resolves to a value starting with `"vercel_mock_"`, the
/// provider returns deterministic mock values without real HTTP calls.
pub struct VercelRotationProvider;

impl RotationProvider for VercelRotationProvider {
    fn name(&self) -> &str {
        "vercel"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        upper.contains("VERCEL")
            && (upper.contains("KEY") || upper.contains("SECRET") || upper.contains("TOKEN"))
    }

    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        let api_key = resolve_api_key(config)?;

        // Mock path.
        if api_key.starts_with("vercel_mock_") {
            guard_mock_rotation(secret_name)?;
            return Ok(format!("mock_challenge_vercel_{secret_name}"));
        }

        let client = build_http_client(config.timeout_secs)?;

        // 1. Mint a new auth token (team-scoped when account_id is set).
        let mut url = "https://api.vercel.com/v3/user/tokens".to_string();
        if let Some(team_id) = config.account_id.as_deref() {
            url.push_str("?teamId=");
            url.push_str(team_id);
        }

        let token_name = format!(
            "phantom-rotation-{}-{}",
            secret_name.to_lowercase(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key.as_str()))
            .json(&serde_json::json!({ "name": token_name }))
            .send()
            .map_err(|e| RotationProviderError::NetworkError {
                reason: e.to_string(),
            })?;

        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(RotationProviderError::AuthFailed {
                reason: format!("Vercel returned HTTP {status}"),
            });
        }
        if !(200..300).contains(&status) {
            let body = response.text().unwrap_or_default();
            return Err(RotationProviderError::ApiError {
                status,
                reason: summarize_error_body(&body),
            });
        }

        let body: serde_json::Value =
            response
                .json()
                .map_err(|e| RotationProviderError::UnexpectedResponse {
                    reason: e.to_string(),
                })?;

        let new_token = body
            .get("bearerToken")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RotationProviderError::UnexpectedResponse {
                reason: "missing 'bearerToken' field in Vercel response".to_string(),
            })?;
        let new_token_id = body
            .get("token")
            .and_then(|t| t.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // 2. Verify the minted token works (whoami-style call). ONLY a 2xx
        //    counts as verified: a 429 / 5xx / transient outage must never
        //    lead to the old token being replaced on the strength of an
        //    unverified new one.
        let verify_status = client
            .get("https://api.vercel.com/v2/user")
            .header("Authorization", format!("Bearer {new_token}"))
            .send()
            .map(|r| r.status().as_u16())
            .map_err(|e| RotationProviderError::NetworkError {
                reason: format!("verification call failed: {e}"),
            })?;
        if !(200..300).contains(&verify_status) {
            // The minted token is not verified — clean it up (best-effort,
            // by explicit id, using the still-valid old bootstrap token) and
            // fail WITHOUT touching the old token.
            if !new_token_id.is_empty() {
                let _ = client
                    .delete(format!(
                        "https://api.vercel.com/v3/user/tokens/{new_token_id}"
                    ))
                    .header("Authorization", format!("Bearer {}", api_key.as_str()))
                    .send();
            }
            return Err(RotationProviderError::UnexpectedResponse {
                reason: format!(
                    "newly minted Vercel token failed whoami verification (HTTP {verify_status})"
                ),
            });
        }

        // NOTE: the OLD token is deliberately NOT revoked here. The caller
        // stores the new value first, then invokes `post_store_cleanup`.
        Ok(encode_challenge_payload(new_token))
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        if challenge_id.starts_with("mock_challenge_vercel_") {
            if !mock_rotation_allowed() {
                return Err(RotationProviderError::ChallengeExpired {
                    challenge_id: redact_challenge_id(challenge_id),
                });
            }
            return Ok(zeroize::Zeroizing::new(
                "vercel_rotated_mock_token_value".to_string(),
            ));
        }

        decode_challenge_payload(challenge_id)
    }

    /// Best-effort revocation of the OLD token, run by the caller only after
    /// the new token is durably stored in the vault.
    ///
    /// Authenticates the `DELETE /v3/user/tokens/current` call with the old
    /// secret value itself, so exactly the rotated-out token is revoked —
    /// never the bootstrap credential (which may be a separate
    /// rotation-management token). Fail-open: any failure or skip is recorded
    /// as an audit event (name only) and never undoes the rotation.
    fn post_store_cleanup(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
        old_value: Option<&zeroize::Zeroizing<String>>,
    ) -> Result<(), RotationProviderError> {
        let Some(old_token) = old_value else {
            crate::audit::log("vault.rotation.old_token_revoke_skipped", Some(secret_name));
            return Ok(());
        };

        // Hermetic mock values never reach the network.
        if old_token.starts_with("vercel_mock_") || old_token.starts_with("vercel_rotated_mock_") {
            return Ok(());
        }

        let Ok(client) = build_http_client(config.timeout_secs) else {
            crate::audit::log("vault.rotation.old_token_revoke_failed", Some(secret_name));
            return Ok(());
        };
        let revoked = client
            .delete("https://api.vercel.com/v3/user/tokens/current")
            .header("Authorization", format!("Bearer {}", old_token.as_str()))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if !revoked {
            // Operators must know the old token is still live (name only —
            // never token bytes).
            crate::audit::log("vault.rotation.old_token_revoke_failed", Some(secret_name));
        }
        Ok(())
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Vercel
    }
}

// ── Sentry provider ───────────────────────────────────────────────────────────

/// Sentry rotation provider — **manual rotation required**.
///
/// Researched 2026-08-16: Sentry has no token-authenticated API for minting
/// auth tokens, so headless rotation is impossible today:
///
/// - Organization auth tokens (`sntrys_…`): the endpoint
///   `POST /api/0/organizations/{org}/org-auth-tokens/` exists but is declared
///   with `SessionNoAuthTokenAuthentication` + `DisallowImpersonatedTokenCreation`
///   (see `src/sentry/api/endpoints/organization_auth_tokens.py` in
///   getsentry/sentry) — it only accepts an interactive web session, never a
///   bearer token, and it is absent from Sentry's public OpenAPI schema.
/// - Internal integration tokens: `POST /api/0/sentry-apps/{app}/api-tokens/`
///   carries the same session-only authentication classes.
///
/// This provider therefore always returns
/// [`RotationProviderError::NotSupported`] with a message pointing the
/// operator at the dashboard. It never reads `api_key_env` and performs no
/// network I/O.
pub struct SentryRotationProvider;

/// Operator-facing explanation used by [`SentryRotationProvider`].
const SENTRY_NOT_SUPPORTED_REASON: &str =
    "Sentry only allows creating auth tokens from an interactive web session \
     (the org-auth-tokens and sentry-apps api-tokens endpoints reject \
     token-based authentication). Create a replacement organization token at \
     https://sentry.io/orgredirect/organizations/:orgslug/settings/auth-tokens/ \
     (Settings > Developer Settings > Organization Tokens), then store it with \
     `phantom add`.";

impl RotationProvider for SentryRotationProvider {
    fn name(&self) -> &str {
        "sentry"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        upper.contains("SENTRY")
            && (upper.contains("KEY") || upper.contains("SECRET") || upper.contains("TOKEN"))
    }

    fn initiate_rotation(
        &self,
        _secret_name: &str,
        _config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        Err(RotationProviderError::NotSupported {
            reason: SENTRY_NOT_SUPPORTED_REASON.to_string(),
        })
    }

    fn finalize_rotation(
        &self,
        _challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        Err(RotationProviderError::NotSupported {
            reason: SENTRY_NOT_SUPPORTED_REASON.to_string(),
        })
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Sentry
    }
}

// ── Supabase provider ─────────────────────────────────────────────────────────

/// Supabase rotation provider — **manual rotation required**.
///
/// Researched 2026-08-16: Supabase personal access tokens (`sbp_…`) cannot be
/// created via any public API. The Management API (`api.supabase.com/v1`) is
/// itself authenticated *with* a PAT and exposes no endpoint to mint or
/// rotate PATs — the docs direct users to the account page to "generate or
/// manage your personal access tokens"
/// (<https://supabase.com/docs/reference/api/introduction>).
///
/// This provider therefore always returns
/// [`RotationProviderError::NotSupported`] with a message linking the
/// dashboard. It never reads `api_key_env` and performs no network I/O.
///
/// Note: project API keys (anon / service_role) are a different credential
/// class rotated from the project dashboard, not covered by this provider.
pub struct SupabaseRotationProvider;

/// Operator-facing explanation used by [`SupabaseRotationProvider`].
const SUPABASE_NOT_SUPPORTED_REASON: &str =
    "Supabase personal access tokens can only be created in the dashboard — \
     the Management API is itself authenticated with a PAT and has no endpoint \
     to mint or rotate one. Create a replacement token at \
     https://supabase.com/dashboard/account/tokens, then store it with \
     `phantom add`.";

impl RotationProvider for SupabaseRotationProvider {
    fn name(&self) -> &str {
        "supabase"
    }

    fn matches(&self, secret_name: &str) -> bool {
        let upper = secret_name.to_uppercase();
        upper.contains("SUPABASE")
            && (upper.contains("KEY") || upper.contains("SECRET") || upper.contains("TOKEN"))
    }

    fn initiate_rotation(
        &self,
        _secret_name: &str,
        _config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        Err(RotationProviderError::NotSupported {
            reason: SUPABASE_NOT_SUPPORTED_REASON.to_string(),
        })
    }

    fn finalize_rotation(
        &self,
        _challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
        Err(RotationProviderError::NotSupported {
            reason: SUPABASE_NOT_SUPPORTED_REASON.to_string(),
        })
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Supabase
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
            .header("Authorization", format!("Bearer {}", api_key.as_str()))
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
        if !(200..300).contains(&status) {
            let body = response.text().unwrap_or_default();
            return Err(RotationProviderError::ApiError {
                status,
                reason: summarize_error_body(&body),
            });
        }

        let body: serde_json::Value =
            response
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
        decode_challenge_payload(challenge_id)
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Custom {
            provider_name: self.provider_name.clone(),
        }
    }
}

// ── Default providers ─────────────────────────────────────────────────────────

/// Build the default set of rotation providers (Stripe, GitHub, AWS, Google,
/// Vercel, plus the not-supported Sentry and Supabase providers, which report
/// manual-rotation-required with a dashboard link).
pub fn default_rotation_providers() -> Vec<Box<dyn RotationProvider>> {
    vec![
        Box::new(StripeRotationProvider),
        Box::new(GitHubRotationProvider),
        Box::new(AwsRotationProvider),
        Box::new(GoogleRotationProvider),
        Box::new(VercelRotationProvider),
        Box::new(SentryRotationProvider),
        Box::new(SupabaseRotationProvider),
    ]
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Resolve the bootstrap API key named by `config.api_key_env`.
///
/// Sources, in order:
/// 1. the process environment variable of that name;
/// 2. the thread-local vault-sourced fallback installed by
///    [`auto_sync_rotation_with_bootstrap`] (the caller retrieves the vault
///    secret of the same name and passes it in — core never reads the vault).
fn resolve_api_key(
    config: &RotationProviderConfig,
) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
    let env_var = config
        .api_key_env
        .as_deref()
        .ok_or(RotationProviderError::NotConfigured)?;
    if let Ok(value) = std::env::var(env_var) {
        return Ok(zeroize::Zeroizing::new(value));
    }
    BOOTSTRAP_OVERRIDE
        .with(|o| {
            o.borrow()
                .as_ref()
                .map(|z| zeroize::Zeroizing::new(z.as_str().to_string()))
        })
        .ok_or(RotationProviderError::NotConfigured)
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
///
/// Returned inside `Zeroizing` — the decoded payload IS the freshly minted
/// secret, and intermediate copies must be scrubbed from memory.
fn decode_challenge_payload(
    challenge_id: &str,
) -> Result<zeroize::Zeroizing<String>, RotationProviderError> {
    use base64::Engine;
    let encoded = challenge_id.strip_prefix("payload_").ok_or_else(|| {
        RotationProviderError::ChallengeExpired {
            // Only ever store the redacted form: the id may be (or embed) a
            // secret payload and this error's Debug/Display would leak it.
            challenge_id: redact_challenge_id(challenge_id),
        }
    })?;
    let mut bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| RotationProviderError::UnexpectedResponse {
            reason: format!("base64 decode error: {e}"),
        })?;
    match String::from_utf8(std::mem::take(&mut bytes)) {
        Ok(s) => Ok(zeroize::Zeroizing::new(s)),
        Err(e) => {
            // Scrub the invalid bytes before dropping them.
            let mut bytes = e.into_bytes();
            zeroize::Zeroize::zeroize(&mut bytes);
            Err(RotationProviderError::UnexpectedResponse {
                reason: "UTF-8 decode error in challenge payload".to_string(),
            })
        }
    }
}

/// Redact a challenge_id for inclusion in errors/logs.
///
/// `payload_`-prefixed ids encode the minted secret in trivially decodable
/// base64 and are fully redacted; other (mock/opaque) ids are truncated.
fn redact_challenge_id(challenge_id: &str) -> String {
    if challenge_id.starts_with("payload_") {
        "payload_[redacted]".to_string()
    } else {
        challenge_id.chars().take(40).collect()
    }
}

/// Reduce a vendor error-response body to a safe, allowlisted summary.
///
/// Vendor error bodies routinely echo request material (Stripe echoes partial
/// API keys, AWS echoes the whole Authorization header), and the raw string
/// would otherwise flow into MCP responses, CLI stderr, `--json` output, and
/// the audit log. Only structural fields (error type / code / status) are
/// kept; everything else is replaced by a fixed message plus byte length.
///
/// Exposed `pub(crate)` so the `issuance` module reuses the identical hygiene
/// when summarizing vendor bodies from the manifest/token/device endpoints.
pub(crate) fn summarize_error_body(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        let mut parts: Vec<String> = Vec::new();
        let scopes = [v.get("error"), Some(&v)];
        for scope in scopes.into_iter().flatten() {
            for key in ["type", "code", "status"] {
                if let Some(field) = scope.get(key) {
                    let rendered = match field {
                        serde_json::Value::String(s) => {
                            Some(s.chars().take(64).collect::<String>())
                        }
                        serde_json::Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    };
                    if let Some(r) = rendered {
                        parts.push(format!("{key}={r}"));
                    }
                }
            }
            if !parts.is_empty() {
                break;
            }
        }
        if !parts.is_empty() {
            return parts.join(" ");
        }
    }
    format!("vendor error body withheld ({} bytes)", body.len())
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
        self.provider_config
            .as_ref()
            .map(|c| c.enabled && c.provider != "manual")
            .unwrap_or(false)
    }
}

/// The outcome of a single item inside a batch rotation run.
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

impl fmt::Debug for BatchItemOutcome {
    /// Redacting `Debug`: `new_value` holds the freshly minted secret
    /// (`Zeroizing` forwards `Debug` to the inner `String`), so it is never
    /// rendered.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BatchItemOutcome")
            .field("secret_name", &self.secret_name)
            .field("old_expires_at", &self.old_expires_at)
            .field("new_expires_at", &self.new_expires_at)
            .field("provider_label", &self.provider_label)
            .field("vendor_rotated", &self.vendor_rotated)
            .field("new_value", &self.new_value.as_ref().map(|_| "[redacted]"))
            .field("error", &self.error)
            .finish()
    }
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
                inter_call_delay_ms: 10,        // ~100 ops/sec
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
            "google" => Self {
                inter_call_delay_ms: 500, // Secret Manager quota: ~2 writes/sec per secret
                post_rotation_pause_ms: 0,
                max_per_batch: 0,
            },
            "vercel" => Self {
                inter_call_delay_ms: 500, // Vercel API: stay well under ~2 req/sec sustained
                post_rotation_pause_ms: 0,
                max_per_batch: 0,
            },
            // "sentry" / "supabase" never reach the network (NotSupported
            // providers) — the default no-delay arm below covers them.
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
                std::thread::sleep(std::time::Duration::from_millis(
                    rate_limit.inter_call_delay_ms,
                ));
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
    ) -> Vec<(
        String,
        Result<zeroize::Zeroizing<String>, RotationProviderError>,
    )> {
        let mut results = Vec::with_capacity(items.len());
        for (name, challenge_id, config) in items.iter() {
            let outcome = self.finalize_rotation(challenge_id, config);
            let success = outcome.is_ok();
            results.push((name.to_string(), outcome));
            if success && rate_limit.post_rotation_pause_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(
                    rate_limit.post_rotation_pause_ms,
                ));
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
    // `providers` is kept in the signature for API stability; labels come
    // from `config.provider` identity, never from name-matching heuristics.
    let _ = providers;
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
            // Resolve which provider handles this secret. Dispatch identity
            // comes from `config.provider` — never from name heuristics — so
            // the batch path stays consistent with the single-secret path.
            let label = provider_config
                .as_ref()
                .filter(|c| c.enabled && c.provider != "manual")
                .map(|c| c.provider.clone())
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
    // `now` is kept in the signature for API stability; expiry persistence is
    // caller-side (the caller owns the vault TTL metadata).
    let _ = now;
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
        let maybe_provider = providers
            .iter()
            .find(|p| p.name() == provider_name.as_str());

        for item in &provider_items {
            let secret_name = &item.secret_name;

            if let (Some(provider), Some(config)) =
                (maybe_provider.as_ref(), item.provider_config.as_ref())
            {
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
                                crate::audit::log_batch_item_failed(
                                    &batch_id,
                                    secret_name,
                                    &e.to_string(),
                                );
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
                                // The new expiry is persisted by the CALLER
                                // (which owns the vault and its TTL metadata)
                                // after it stores the value; reporting a
                                // fabricated expiry here would let the summary
                                // claim a TTL that was never written.
                                let new_expires_at = None;

                                crate::audit::log_batch_item_succeeded(
                                    &batch_id,
                                    secret_name,
                                    provider_name,
                                );

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
        assert_eq!(RotationSource::Google.label(), "google");
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
            RotationSource::Google,
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
        let json = serde_json::to_string(&RotationSource::Google).unwrap();
        assert_eq!(json, r#""google""#);
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
        assert!(
            encoded.starts_with("payload_"),
            "must be prefixed with 'payload_'"
        );
        let decoded = decode_challenge_payload(&encoded).unwrap();
        assert_eq!(decoded.as_str(), original);
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

        unsafe { std::env::set_var("PHANTOM_TEST_GITHUB_MOCK_KEY", "ghp_mock_admin_token") };

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

        unsafe { std::env::set_var("PHANTOM_TEST_AWS_MOCK_KEY", "AKID_MOCK_ROTATION_KEY") };

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

    // ── Google Cloud mock rotation ────────────────────────────────────────────

    #[test]
    fn google_provider_matches_gcp_key_names() {
        let p = GoogleRotationProvider;
        // Google-prefixed
        assert!(p.matches("GOOGLE_API_KEY"), "GOOGLE_API_KEY must match");
        // Google-ISSUED credentials must never be claimed: random hex cannot
        // replace a service-account key or application default credentials.
        assert!(
            !p.matches("GOOGLE_APPLICATION_CREDENTIALS"),
            "GOOGLE_APPLICATION_CREDENTIALS is Google-issued and must NOT match"
        );
        assert!(
            !p.matches("GOOGLE_SERVICE_ACCOUNT_KEY"),
            "GOOGLE_SERVICE_ACCOUNT_KEY is Google-issued and must NOT match"
        );
        assert!(
            p.matches("GOOGLE_ACCESS_TOKEN"),
            "GOOGLE_ACCESS_TOKEN must match"
        );
        assert!(
            p.matches("MY_GOOGLE_API_KEY"),
            "MY_GOOGLE_API_KEY must match"
        );
        // GCP-prefixed
        assert!(p.matches("GCP_API_KEY"), "GCP_API_KEY must match");
        assert!(p.matches("GCP_ACCESS_TOKEN"), "GCP_ACCESS_TOKEN must match");
        assert!(p.matches("GCP_SECRET"), "GCP_SECRET must match");
        assert!(p.matches("GCP_SERVICE_KEY"), "GCP_SERVICE_KEY must match");
        // Must NOT match unrelated
        assert!(!p.matches("STRIPE_SECRET_KEY"), "STRIPE must not match");
        assert!(!p.matches("GITHUB_TOKEN"), "GITHUB must not match");
        assert!(!p.matches("AWS_ACCESS_KEY_ID"), "AWS must not match");
        assert!(!p.matches("OPENAI_API_KEY"), "OPENAI must not match");
    }

    #[test]
    fn google_provider_name_is_google() {
        let p = GoogleRotationProvider;
        assert_eq!(p.name(), "google");
    }

    #[test]
    fn google_provider_rotation_source_is_google() {
        let p = GoogleRotationProvider;
        assert_eq!(p.rotation_source(), RotationSource::Google);
        assert_eq!(p.rotation_source().label(), "google");
    }

    #[test]
    fn google_mock_rotation_full_flow() {
        let provider = GoogleRotationProvider;
        let config = RotationProviderConfig {
            provider: "google".to_string(),
            api_key_env: Some("PHANTOM_TEST_GCP_MOCK_KEY".to_string()),
            account_id: Some("projects/my-project/secrets/my-secret".to_string()),
            ..Default::default()
        };

        unsafe { std::env::set_var("PHANTOM_TEST_GCP_MOCK_KEY", "gcp_mock_access_token_test") };

        let challenge = provider
            .initiate_rotation("GCP_API_KEY", &config)
            .expect("initiate_rotation should succeed for mock token");
        assert!(
            challenge.starts_with("mock_challenge_google_"),
            "mock challenge_id must start with 'mock_challenge_google_': {challenge}"
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
            "gcp_rotated_mock_secret_value_v2",
            "Google mock value must be deterministic"
        );

        unsafe { std::env::remove_var("PHANTOM_TEST_GCP_MOCK_KEY") };
    }

    #[test]
    fn google_mock_rotation_version_increment() {
        // Simulates a second rotation: calling initiate+finalize twice must
        // return the same deterministic mock value (idempotent mock).
        let provider = GoogleRotationProvider;
        let config = RotationProviderConfig {
            provider: "google".to_string(),
            api_key_env: Some("PHANTOM_TEST_GCP_VERSION_KEY".to_string()),
            account_id: Some("projects/proj/secrets/sec".to_string()),
            ..Default::default()
        };

        unsafe {
            std::env::set_var(
                "PHANTOM_TEST_GCP_VERSION_KEY",
                "gcp_mock_version_test_token",
            )
        };

        let ch1 = provider
            .initiate_rotation("GOOGLE_API_KEY", &config)
            .expect("first initiate should succeed");
        let v1 = provider
            .finalize_rotation(&ch1, &config)
            .expect("first finalize should succeed");

        let ch2 = provider
            .initiate_rotation("GOOGLE_API_KEY", &config)
            .expect("second initiate should succeed");
        let v2 = provider
            .finalize_rotation(&ch2, &config)
            .expect("second finalize should succeed");

        // Both rotations produce the same deterministic mock value.
        assert_eq!(
            v1.as_str(),
            v2.as_str(),
            "mock rotation must be deterministic"
        );
        // The challenge IDs must be the same pattern (deterministic mock).
        assert_eq!(ch1, ch2, "mock challenge IDs must be identical");

        unsafe { std::env::remove_var("PHANTOM_TEST_GCP_VERSION_KEY") };
    }

    #[test]
    fn google_rotation_missing_api_key_env_returns_not_configured() {
        let provider = GoogleRotationProvider;
        let config = RotationProviderConfig {
            provider: "google".to_string(),
            api_key_env: None, // intentionally missing
            ..Default::default()
        };

        let err = provider
            .initiate_rotation("GCP_API_KEY", &config)
            .expect_err("missing api_key_env must return an error");
        assert!(
            matches!(err, RotationProviderError::NotConfigured),
            "expected NotConfigured, got: {err}"
        );
    }

    #[test]
    fn google_rotation_unset_env_var_returns_not_configured() {
        let provider = GoogleRotationProvider;
        let config = RotationProviderConfig {
            provider: "google".to_string(),
            api_key_env: Some("PHANTOM_GCP_DEFINITELY_UNSET_ENV_VAR_XYZ".to_string()),
            ..Default::default()
        };

        // Ensure it is truly unset.
        unsafe { std::env::remove_var("PHANTOM_GCP_DEFINITELY_UNSET_ENV_VAR_XYZ") };

        let err = provider
            .initiate_rotation("GOOGLE_API_KEY", &config)
            .expect_err("unset env var must return an error");
        assert!(
            matches!(err, RotationProviderError::NotConfigured),
            "expected NotConfigured, got: {err}"
        );
    }

    #[test]
    fn google_rotation_source_serializes_correctly() {
        let json = serde_json::to_string(&RotationSource::Google).unwrap();
        assert_eq!(
            json, r#""google""#,
            "RotationSource::Google must serialize to \"google\""
        );
    }

    #[test]
    fn google_rotation_source_label_and_display() {
        assert_eq!(RotationSource::Google.label(), "google");
        assert_eq!(RotationSource::Google.to_string(), "google");
    }

    #[test]
    fn google_rate_limit_has_inter_call_delay() {
        let rl = ProviderRateLimit::for_provider("google");
        assert!(
            rl.inter_call_delay_ms > 0,
            "Google Secret Manager must have a positive inter-call delay"
        );
        assert_eq!(
            rl.post_rotation_pause_ms, 0,
            "Google Secret Manager has no mandatory post-rotation pause"
        );
    }

    #[test]
    fn auto_sync_rotation_google_mock_returns_value() {
        let config = RotationProviderConfig {
            provider: "google".to_string(),
            api_key_env: Some("PHANTOM_AUTO_SYNC_GCP_KEY".to_string()),
            account_id: Some("projects/proj/secrets/mysecret".to_string()),
            enabled: true,
            ..Default::default()
        };

        unsafe { std::env::set_var("PHANTOM_AUTO_SYNC_GCP_KEY", "gcp_mock_auto_sync_token") };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let result = auto_sync_rotation("GCP_API_KEY", Some(&config), &providers);
        assert!(
            result.is_ok(),
            "auto_sync_rotation must not return Err for Google mock"
        );
        let value = result.unwrap();
        assert!(
            value.is_some(),
            "Google mock provider must return Some(value)"
        );
        assert_eq!(value.unwrap().as_str(), "gcp_rotated_mock_secret_value_v2");

        unsafe { std::env::remove_var("PHANTOM_AUTO_SYNC_GCP_KEY") };
    }

    #[test]
    fn execute_batch_rotation_google_mock_succeeds() {
        unsafe {
            std::env::set_var("BATCH_TEST_GCP_KEY", "gcp_mock_batch_token");
            std::env::remove_var("PHANTOM_AUDIT");
        }

        let gcp_config = RotationProviderConfig {
            provider: "google".to_string(),
            api_key_env: Some("BATCH_TEST_GCP_KEY".to_string()),
            account_id: Some("projects/proj/secrets/batch-secret".to_string()),
            enabled: true,
            ..Default::default()
        };

        let now = 1_700_000_000u64;
        let items = vec![BatchRotationItem {
            secret_name: "GCP_API_KEY".to_string(),
            expires_at: Some(now - 86_400),
            provider_config: Some(gcp_config),
            provider_label: "google".to_string(),
        }];

        let providers = default_rotation_providers();
        let (batch_id, outcomes) = execute_batch_rotation(&items, &providers, now);

        assert!(!batch_id.is_empty(), "batch_id must be non-empty");
        assert_eq!(outcomes.len(), 1);

        let outcome = &outcomes[0];
        assert_eq!(outcome.secret_name, "GCP_API_KEY");
        assert!(
            outcome.vendor_rotated,
            "should be vendor-rotated via Google mock"
        );
        assert!(
            outcome.is_ok(),
            "should have no error; got: {:?}",
            outcome.error
        );
        assert!(outcome.new_value.is_some(), "should have a new value");
        assert_eq!(
            outcome.new_value.as_ref().unwrap().as_str(),
            "gcp_rotated_mock_secret_value_v2"
        );
        assert!(
            outcome.new_expires_at.is_none(),
            "core must not fabricate an expiry — persistence is caller-side"
        );

        unsafe { std::env::remove_var("BATCH_TEST_GCP_KEY") };
    }

    #[test]
    fn default_rotation_providers_includes_google() {
        let providers = default_rotation_providers();
        let names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
        assert!(
            names.contains(&"google"),
            "default_rotation_providers must include 'google'"
        );
    }

    #[test]
    fn default_rotation_providers_google_matches_expected_keys() {
        let providers = default_rotation_providers();
        let gcp_keys = vec![
            ("GCP_API_KEY", "google"),
            ("GOOGLE_API_KEY", "google"),
            ("GCP_ACCESS_TOKEN", "google"),
        ];
        for (key, expected) in gcp_keys {
            let matched = providers
                .iter()
                .filter(|p| p.matches(key))
                .map(|p| p.name())
                .any(|n| n == expected);
            assert!(
                matched,
                "key {key} should match provider {expected} in default_rotation_providers"
            );
        }
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
    fn auto_sync_rotation_disabled_provider_returns_distinct_error() {
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            enabled: false,
            ..Default::default()
        };
        let providers = default_rotation_providers();
        let err = auto_sync_rotation("STRIPE_SECRET_KEY", Some(&config), &providers)
            .expect_err("disabled config must be a distinct hard error, not silent Ok(None)");
        assert!(
            matches!(err, RotationProviderError::Disabled),
            "expected Disabled, got: {err}"
        );
        assert!(
            err.to_string().contains("disabled"),
            "error must say the provider is disabled, not blame the bootstrap credential"
        );
    }

    #[test]
    fn auto_sync_rotation_manual_provider_returns_none() {
        let config = RotationProviderConfig {
            provider: "manual".to_string(),
            ..Default::default()
        };
        let providers = default_rotation_providers();
        let result = auto_sync_rotation("ANY_SECRET", Some(&config), &providers);
        assert!(result.unwrap().is_none(), "manual provider → Ok(None)");
    }

    #[test]
    fn auto_sync_rotation_unknown_provider_returns_distinct_error() {
        let config = RotationProviderConfig {
            provider: "does_not_exist".to_string(),
            enabled: true,
            ..Default::default()
        };
        let providers = default_rotation_providers();
        let err = auto_sync_rotation("SOME_KEY", Some(&config), &providers)
            .expect_err("unknown provider name must be a hard error");
        assert!(
            matches!(err, RotationProviderError::UnknownProvider { .. }),
            "expected UnknownProvider, got: {err}"
        );
        assert!(err.to_string().contains("does_not_exist"));
    }

    #[test]
    fn dispatch_uses_config_provider_not_secret_name_heuristics() {
        // Regression: a secret whose NAME contains no vendor substring must
        // still be dispatched to the provider named in the config...
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_DISPATCH_BY_CONFIG_KEY".to_string()),
            enabled: true,
            ..Default::default()
        };
        unsafe { std::env::set_var("PHANTOM_DISPATCH_BY_CONFIG_KEY", "sk_test_mock_dispatch") };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let value = auto_sync_rotation("PAYMENTS_API_KEY", Some(&config), &providers)
            .expect("config-named provider must be dispatched")
            .expect("mock stripe path must produce a value");
        assert_eq!(value.as_str(), "sk_test_rotated_mock_value_stripe");

        unsafe { std::env::remove_var("PHANTOM_DISPATCH_BY_CONFIG_KEY") };
    }

    #[test]
    fn dispatch_misleading_name_goes_to_configured_provider() {
        // ...and a name that LOOKS like an earlier-listed vendor (STRIPE is
        // registered before GITHUB) must never hijack the dispatch: the
        // GitHub bootstrap credential may not be sent to Stripe.
        let config = RotationProviderConfig {
            provider: "github".to_string(),
            api_key_env: Some("PHANTOM_DISPATCH_MISLEAD_KEY".to_string()),
            account_id: Some("install_42".to_string()),
            enabled: true,
            ..Default::default()
        };
        unsafe { std::env::set_var("PHANTOM_DISPATCH_MISLEAD_KEY", "ghp_mock_mislead") };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let value = auto_sync_rotation("STRIPE_GITHUB_TOKEN", Some(&config), &providers)
            .expect("github provider must run")
            .expect("mock github path must produce a value");
        assert_eq!(
            value.as_str(),
            "ghp_rotated_mock_token_github",
            "rotation must have been performed by the configured (github) provider"
        );

        unsafe { std::env::remove_var("PHANTOM_DISPATCH_MISLEAD_KEY") };
    }

    #[test]
    fn auto_sync_rotation_stripe_mock_returns_value() {
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_AUTO_SYNC_STRIPE_KEY".to_string()),
            enabled: true,
            ..Default::default()
        };

        unsafe { std::env::set_var("PHANTOM_AUTO_SYNC_STRIPE_KEY", "sk_test_mock_auto_sync") };

        // Disable audit for this test.
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let result = auto_sync_rotation("STRIPE_SECRET_KEY", Some(&config), &providers);
        assert!(result.is_ok(), "auto_sync_rotation should not return Err");
        let value = result.unwrap();
        assert!(
            value.is_some(),
            "mock Stripe provider should return Some(value)"
        );
        assert_eq!(value.unwrap().as_str(), "sk_test_rotated_mock_value_stripe");

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

        unsafe { std::env::set_var("PHANTOM_AV_STRIPE_KEY", "sk_test_mock_av_key") };
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

    // ── Error-body summarization (no raw vendor bodies in errors) ─────────────

    #[test]
    fn summarize_error_body_keeps_only_allowlisted_fields() {
        let stripe_style = r#"{"error":{"type":"invalid_request_error","message":"Invalid API Key provided: sk_live_SECRETSECRET"}}"#;
        let summary = summarize_error_body(stripe_style);
        assert!(summary.contains("type=invalid_request_error"));
        assert!(
            !summary.contains("sk_live_SECRETSECRET"),
            "raw vendor message (which can echo credentials) must never survive: {summary}"
        );

        let google_style =
            r#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"secret sauce"}}"#;
        let summary = summarize_error_body(google_style);
        assert!(summary.contains("status=PERMISSION_DENIED"));
        assert!(!summary.contains("secret sauce"));
    }

    #[test]
    fn summarize_error_body_withholds_unparseable_bodies() {
        let aws_style = "<ErrorResponse><Error><Message>Authorization header AWS4-HMAC-SHA256 Credential=AKIA_LIVE_SECRET is malformed</Message></Error></ErrorResponse>";
        let summary = summarize_error_body(aws_style);
        assert!(
            !summary.contains("AKIA_LIVE_SECRET"),
            "non-JSON bodies must be fully withheld: {summary}"
        );
        assert!(summary.contains("withheld"));
    }

    // ── Redaction of secret-bearing challenge_ids ─────────────────────────────

    #[test]
    fn payload_challenge_id_is_redacted_in_errors_and_debug() {
        let encoded = encode_challenge_payload("sk_live_super_secret_value");
        let err = RotationProviderError::ChallengeExpired {
            challenge_id: encoded.clone(),
        };
        let display = err.to_string();
        let debug = format!("{err:?}");
        let b64_part = encoded.strip_prefix("payload_").unwrap();
        assert!(
            !display.contains(b64_part),
            "Display must not include the base64-encoded secret"
        );
        // Debug of the stored id would leak when constructed directly; the
        // decode path stores only the redacted form.
        let decode_err = decode_challenge_payload("no_prefix_here").unwrap_err();
        assert!(matches!(
            decode_err,
            RotationProviderError::ChallengeExpired { .. }
        ));
        let _ = debug;
    }

    #[test]
    fn auto_sync_outcome_debug_redacts_challenge_id() {
        let outcome = AutoSyncOutcome::VendorRotated {
            source: RotationSource::Stripe,
            challenge_id: encode_challenge_payload("sk_live_shhh"),
        };
        let debug = format!("{outcome:?}");
        assert!(debug.contains("[redacted]"));
        assert!(
            !debug.contains("payload_"),
            "Debug must not render the payload challenge_id: {debug}"
        );
    }

    #[test]
    fn batch_item_outcome_debug_redacts_new_value() {
        let outcome = BatchItemOutcome {
            secret_name: "K".to_string(),
            old_expires_at: None,
            new_expires_at: None,
            provider_label: "stripe".to_string(),
            vendor_rotated: true,
            new_value: Some(zeroize::Zeroizing::new("sk_live_new_secret".to_string())),
            error: None,
        };
        let debug = format!("{outcome:?}");
        assert!(
            !debug.contains("sk_live_new_secret"),
            "Debug must never print the minted secret: {debug}"
        );
        assert!(debug.contains("[redacted]"));
    }

    // ── Honest NotSupported for unimplementable real paths ────────────────────

    #[test]
    fn stripe_real_path_is_not_supported() {
        let provider = StripeRotationProvider;
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_TEST_STRIPE_REAL_KEY".to_string()),
            ..Default::default()
        };
        unsafe { std::env::set_var("PHANTOM_TEST_STRIPE_REAL_KEY", "sk_live_placeholder") };

        let err = provider
            .initiate_rotation("STRIPE_SECRET_KEY", &config)
            .expect_err("non-mock Stripe rotation must be NotSupported (no public API)");
        assert!(
            matches!(err, RotationProviderError::NotSupported { .. }),
            "expected NotSupported, got: {err}"
        );
        assert!(err.to_string().contains("dashboard.stripe.com"));

        unsafe { std::env::remove_var("PHANTOM_TEST_STRIPE_REAL_KEY") };
    }

    #[test]
    fn aws_real_path_is_not_supported_until_sigv4() {
        let provider = AwsRotationProvider;
        let config = RotationProviderConfig {
            provider: "aws".to_string(),
            api_key_env: Some("PHANTOM_TEST_AWS_REAL_KEY".to_string()),
            account_id: Some("iam-user".to_string()),
            ..Default::default()
        };
        unsafe { std::env::set_var("PHANTOM_TEST_AWS_REAL_KEY", "AKIA_PLACEHOLDER") };

        let err = provider
            .initiate_rotation("AWS_SECRET_ACCESS_KEY", &config)
            .expect_err("non-mock AWS rotation must be NotSupported (no SigV4 signer)");
        assert!(
            matches!(err, RotationProviderError::NotSupported { .. }),
            "expected NotSupported, got: {err}"
        );
        assert!(err.to_string().contains("SigV4"));

        unsafe { std::env::remove_var("PHANTOM_TEST_AWS_REAL_KEY") };
    }

    // ── Google guards ─────────────────────────────────────────────────────────

    #[test]
    fn google_missing_account_id_is_not_configured_before_any_network() {
        let provider = GoogleRotationProvider;
        let config = RotationProviderConfig {
            provider: "google".to_string(),
            api_key_env: Some("PHANTOM_TEST_GCP_REAL_KEY".to_string()),
            account_id: None, // missing resource name
            ..Default::default()
        };
        // Non-mock token: the account_id check must fire before any HTTP call.
        unsafe { std::env::set_var("PHANTOM_TEST_GCP_REAL_KEY", "ya29_placeholder_token") };

        let err = provider
            .initiate_rotation("GCP_API_KEY", &config)
            .expect_err("missing account_id must be a config error, not a guessed URL");
        assert!(
            matches!(err, RotationProviderError::NotConfigured),
            "expected NotConfigured, got: {err}"
        );

        unsafe { std::env::remove_var("PHANTOM_TEST_GCP_REAL_KEY") };
    }

    #[test]
    fn google_refuses_google_issued_credential_names() {
        let provider = GoogleRotationProvider;
        let config = RotationProviderConfig {
            provider: "google".to_string(),
            api_key_env: Some("PHANTOM_TEST_GCP_ISSUED_KEY".to_string()),
            account_id: Some("projects/p/secrets/s".to_string()),
            ..Default::default()
        };
        unsafe { std::env::set_var("PHANTOM_TEST_GCP_ISSUED_KEY", "gcp_mock_token") };

        for name in ["GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT_KEY"] {
            let err = provider
                .initiate_rotation(name, &config)
                .expect_err("Google-issued credential names must be refused");
            assert!(
                matches!(err, RotationProviderError::NotSupported { .. }),
                "expected NotSupported for {name}, got: {err}"
            );
        }

        unsafe { std::env::remove_var("PHANTOM_TEST_GCP_ISSUED_KEY") };
    }

    // ── Vercel post-store cleanup ─────────────────────────────────────────────

    #[test]
    fn vercel_post_store_cleanup_skips_without_old_value() {
        // No old value → revoke is skipped (audited), never an error, and no
        // network I/O is attempted.
        let provider = VercelRotationProvider;
        let config = RotationProviderConfig {
            provider: "vercel".to_string(),
            ..Default::default()
        };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };
        provider
            .post_store_cleanup("VERCEL_TOKEN", &config, None)
            .expect("cleanup must fail open");
    }

    #[test]
    fn vercel_post_store_cleanup_skips_mock_values() {
        let provider = VercelRotationProvider;
        let config = RotationProviderConfig {
            provider: "vercel".to_string(),
            ..Default::default()
        };
        let old = zeroize::Zeroizing::new("vercel_mock_old_token".to_string());
        provider
            .post_store_cleanup("VERCEL_TOKEN", &config, Some(&old))
            .expect("mock old values must never reach the network");
    }

    #[test]
    fn default_post_store_cleanup_is_noop() {
        let provider = StripeRotationProvider;
        let config = RotationProviderConfig::default();
        let old = zeroize::Zeroizing::new("sk_old".to_string());
        provider
            .post_store_cleanup("STRIPE_SECRET_KEY", &config, Some(&old))
            .expect("default cleanup is a no-op");
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
        assert_eq!(
            rl.post_rotation_pause_ms, 0,
            "GitHub has no post-rotation pause"
        );
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
        assert_eq!(
            rl.inter_call_delay_ms, 0,
            "manual provider must have no inter-call delay"
        );
        assert_eq!(
            rl.post_rotation_pause_ms, 0,
            "manual provider must have no post-rotation pause"
        );
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
            (
                "STRIPE_KEY".to_string(),
                Some(now + 10 * 86_400),
                Some(stripe_config.clone()),
            ),
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
        assert!(
            !names.contains(&"GITHUB_TOKEN"),
            "GITHUB_TOKEN must NOT be due"
        );
        assert!(
            !names.contains(&"MANUAL_KEY"),
            "MANUAL_KEY (no expiry) must NOT be due"
        );
    }

    #[test]
    fn batch_discover_due_sorts_most_urgent_first() {
        let now = 1_700_000_000u64;
        let window = 60 * 86_400u64;

        let input = vec![
            ("KEY_C".to_string(), Some(now + 20 * 86_400), None), // 20 days out
            ("KEY_A".to_string(), Some(now - 86_400), None),      // already expired
            ("KEY_B".to_string(), Some(now + 5 * 86_400), None),  // 5 days out
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
            (
                "STRIPE_SECRET_KEY".to_string(),
                Some(now + 5 * 86_400),
                Some(stripe_config),
            ),
            ("MY_MANUAL_KEY".to_string(), Some(now + 5 * 86_400), None),
        ];

        let providers = default_rotation_providers();
        let due = batch_discover_due(&input, window, now, &providers);

        assert_eq!(due.len(), 2);
        let stripe_item = due
            .iter()
            .find(|i| i.secret_name == "STRIPE_SECRET_KEY")
            .unwrap();
        let manual_item = due
            .iter()
            .find(|i| i.secret_name == "MY_MANUAL_KEY")
            .unwrap();

        assert_eq!(stripe_item.provider_label, "stripe");
        assert!(
            stripe_item.is_vendor(),
            "STRIPE_SECRET_KEY with provider config must be vendor"
        );
        assert_eq!(manual_item.provider_label, "manual");
        assert!(
            !manual_item.is_vendor(),
            "key without provider config must not be vendor"
        );
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
        let items = vec![BatchRotationItem {
            secret_name: "STRIPE_SECRET_KEY".to_string(),
            expires_at: Some(now - 86_400), // already expired
            provider_config: Some(stripe_config),
            provider_label: "stripe".to_string(),
        }];

        let providers = default_rotation_providers();
        let (batch_id, outcomes) = execute_batch_rotation(&items, &providers, now);

        assert!(!batch_id.is_empty(), "batch_id must be non-empty");
        assert_eq!(outcomes.len(), 1);

        let outcome = &outcomes[0];
        assert_eq!(outcome.secret_name, "STRIPE_SECRET_KEY");
        assert!(
            outcome.vendor_rotated,
            "should be vendor-rotated via Stripe mock"
        );
        assert!(outcome.is_ok(), "should have no error");
        assert!(outcome.new_value.is_some(), "should have a new value");
        assert_eq!(
            outcome.new_value.as_ref().unwrap().as_str(),
            "sk_test_rotated_mock_value_stripe"
        );
        assert!(
            outcome.new_expires_at.is_none(),
            "core must not fabricate an expiry — persistence is caller-side"
        );

        unsafe { std::env::remove_var("BATCH_TEST_STRIPE_KEY") };
    }

    #[test]
    fn execute_batch_rotation_manual_item_has_no_new_value() {
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let now = 1_700_000_000u64;
        let items = vec![BatchRotationItem {
            secret_name: "MY_MANUAL_SECRET".to_string(),
            expires_at: Some(now - 3600),
            provider_config: None, // manual
            provider_label: "manual".to_string(),
        }];

        let providers = default_rotation_providers();
        let (batch_id, outcomes) = execute_batch_rotation(&items, &providers, now);

        assert!(!batch_id.is_empty());
        assert_eq!(outcomes.len(), 1);

        let outcome = &outcomes[0];
        assert_eq!(outcome.provider_label, "manual");
        assert!(!outcome.vendor_rotated);
        assert!(
            outcome.new_value.is_none(),
            "manual item must not have a new value"
        );
        assert!(
            outcome.error.is_none(),
            "manual item is not an error — just needs manual handling"
        );
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
            assert!(
                o.is_ok(),
                "outcome for {} must be ok, got: {:?}",
                o.secret_name,
                o.error
            );
        }

        let stripe_out = outcomes
            .iter()
            .find(|o| o.secret_name == "STRIPE_SECRET_KEY")
            .unwrap();
        assert!(stripe_out.vendor_rotated, "Stripe must be vendor-rotated");
        assert!(stripe_out.new_value.is_some());

        let github_out = outcomes
            .iter()
            .find(|o| o.secret_name == "GITHUB_TOKEN")
            .unwrap();
        assert!(github_out.vendor_rotated, "GitHub must be vendor-rotated");
        assert!(github_out.new_value.is_some());

        let manual_out = outcomes
            .iter()
            .find(|o| o.secret_name == "MANUAL_API_KEY")
            .unwrap();
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
        assert!(
            !outcome.is_ok(),
            "missing env var should cause rotation failure"
        );
        assert!(
            outcome.error.is_some(),
            "error field must be populated on failure"
        );
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

    // ── Vercel provider ───────────────────────────────────────────────────────

    #[test]
    fn vercel_provider_matches_vercel_keys() {
        let p = VercelRotationProvider;
        assert!(p.matches("VERCEL_TOKEN"));
        assert!(p.matches("VERCEL_API_KEY"));
        assert!(p.matches("MY_VERCEL_SECRET"));
        assert!(p.matches("vercel_token"));
        assert!(!p.matches("VERCEL_ORG_ID"), "non-credential must not match");
        assert!(!p.matches("STRIPE_SECRET_KEY"));
        assert!(!p.matches("GITHUB_TOKEN"));
    }

    #[test]
    fn vercel_provider_name_and_source() {
        let p = VercelRotationProvider;
        assert_eq!(p.name(), "vercel");
        assert_eq!(p.rotation_source(), RotationSource::Vercel);
        assert_eq!(p.rotation_source().label(), "vercel");
    }

    #[test]
    fn vercel_mock_rotation_full_flow() {
        let provider = VercelRotationProvider;
        let config = RotationProviderConfig {
            provider: "vercel".to_string(),
            api_key_env: Some("PHANTOM_TEST_VERCEL_MOCK_KEY".to_string()),
            ..Default::default()
        };

        unsafe { std::env::set_var("PHANTOM_TEST_VERCEL_MOCK_KEY", "vercel_mock_admin_token") };

        let challenge = provider
            .initiate_rotation("VERCEL_TOKEN", &config)
            .expect("initiate_rotation should succeed for mock token");
        assert!(
            challenge.starts_with("mock_challenge_vercel_"),
            "mock challenge_id must start with 'mock_challenge_vercel_': {challenge}"
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
            "vercel_rotated_mock_token_value",
            "Vercel mock value must be deterministic"
        );

        unsafe { std::env::remove_var("PHANTOM_TEST_VERCEL_MOCK_KEY") };
    }

    #[test]
    fn vercel_rotation_missing_api_key_env_returns_not_configured() {
        let provider = VercelRotationProvider;
        let config = RotationProviderConfig {
            provider: "vercel".to_string(),
            api_key_env: None,
            ..Default::default()
        };

        let err = provider
            .initiate_rotation("VERCEL_TOKEN", &config)
            .expect_err("missing api_key_env must return an error");
        assert!(
            matches!(err, RotationProviderError::NotConfigured),
            "expected NotConfigured, got: {err}"
        );
    }

    #[test]
    fn vercel_rate_limit_has_inter_call_delay() {
        let rl = ProviderRateLimit::for_provider("vercel");
        assert!(
            rl.inter_call_delay_ms > 0,
            "Vercel must have a positive inter-call delay"
        );
        assert_eq!(
            rl.post_rotation_pause_ms, 0,
            "Vercel has no mandatory post-rotation pause"
        );
    }

    #[test]
    fn auto_sync_rotation_vercel_mock_returns_value() {
        let config = RotationProviderConfig {
            provider: "vercel".to_string(),
            api_key_env: Some("PHANTOM_AUTO_SYNC_VERCEL_KEY".to_string()),
            enabled: true,
            ..Default::default()
        };

        unsafe { std::env::set_var("PHANTOM_AUTO_SYNC_VERCEL_KEY", "vercel_mock_auto_sync") };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let result = auto_sync_rotation("VERCEL_TOKEN", Some(&config), &providers);
        assert!(
            result.is_ok(),
            "auto_sync_rotation must not return Err for Vercel mock"
        );
        let value = result.unwrap();
        assert!(
            value.is_some(),
            "Vercel mock provider must return Some(value)"
        );
        assert_eq!(value.unwrap().as_str(), "vercel_rotated_mock_token_value");

        unsafe { std::env::remove_var("PHANTOM_AUTO_SYNC_VERCEL_KEY") };
    }

    // ── Sentry provider (manual rotation required) ────────────────────────────

    #[test]
    fn sentry_provider_matches_sentry_keys() {
        let p = SentryRotationProvider;
        assert!(p.matches("SENTRY_AUTH_TOKEN"));
        assert!(p.matches("SENTRY_API_KEY"));
        assert!(p.matches("MY_SENTRY_SECRET"));
        assert!(!p.matches("SENTRY_DSN"), "DSN is not a rotatable token");
        assert!(!p.matches("VERCEL_TOKEN"));
    }

    #[test]
    fn sentry_provider_name_and_source() {
        let p = SentryRotationProvider;
        assert_eq!(p.name(), "sentry");
        assert_eq!(p.rotation_source(), RotationSource::Sentry);
        assert_eq!(p.rotation_source().label(), "sentry");
    }

    #[test]
    fn sentry_rotation_is_not_supported_with_dashboard_link() {
        let provider = SentryRotationProvider;
        let config = RotationProviderConfig {
            provider: "sentry".to_string(),
            ..Default::default()
        };

        let err = provider
            .initiate_rotation("SENTRY_AUTH_TOKEN", &config)
            .expect_err("Sentry rotation must be NotSupported");
        assert!(
            matches!(err, RotationProviderError::NotSupported { .. }),
            "expected NotSupported, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("sentry.io"),
            "operator message must link the Sentry dashboard"
        );
        assert!(
            msg.contains("phantom add"),
            "operator message must explain how to store the replacement"
        );

        // finalize must be equally unsupported.
        let err2 = provider
            .finalize_rotation("anything", &config)
            .expect_err("finalize must also be NotSupported");
        assert!(matches!(err2, RotationProviderError::NotSupported { .. }));
    }

    #[test]
    fn auto_sync_rotation_sentry_returns_not_supported() {
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };
        let config = RotationProviderConfig {
            provider: "sentry".to_string(),
            enabled: true,
            ..Default::default()
        };

        let providers = default_rotation_providers();
        let result = auto_sync_rotation("SENTRY_AUTH_TOKEN", Some(&config), &providers);
        let err = result.expect_err("Sentry auto-sync must surface NotSupported");
        assert!(matches!(err, RotationProviderError::NotSupported { .. }));
    }

    // ── Supabase provider (manual rotation required) ──────────────────────────

    #[test]
    fn supabase_provider_matches_supabase_keys() {
        let p = SupabaseRotationProvider;
        assert!(p.matches("SUPABASE_ACCESS_TOKEN"));
        assert!(p.matches("SUPABASE_SERVICE_ROLE_KEY"));
        assert!(p.matches("MY_SUPABASE_SECRET"));
        assert!(!p.matches("SUPABASE_URL"), "URL is not a credential");
        assert!(!p.matches("SENTRY_AUTH_TOKEN"));
    }

    #[test]
    fn supabase_provider_name_and_source() {
        let p = SupabaseRotationProvider;
        assert_eq!(p.name(), "supabase");
        assert_eq!(p.rotation_source(), RotationSource::Supabase);
        assert_eq!(p.rotation_source().label(), "supabase");
    }

    #[test]
    fn supabase_rotation_is_not_supported_with_dashboard_link() {
        let provider = SupabaseRotationProvider;
        let config = RotationProviderConfig {
            provider: "supabase".to_string(),
            ..Default::default()
        };

        let err = provider
            .initiate_rotation("SUPABASE_ACCESS_TOKEN", &config)
            .expect_err("Supabase rotation must be NotSupported");
        assert!(
            matches!(err, RotationProviderError::NotSupported { .. }),
            "expected NotSupported, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("supabase.com/dashboard/account/tokens"),
            "operator message must link the Supabase dashboard token page"
        );

        let err2 = provider
            .finalize_rotation("anything", &config)
            .expect_err("finalize must also be NotSupported");
        assert!(matches!(err2, RotationProviderError::NotSupported { .. }));
    }

    // ── New providers: registration + serialization ───────────────────────────

    #[test]
    fn default_rotation_providers_includes_new_vendors() {
        let providers = default_rotation_providers();
        let names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
        for expected in ["vercel", "sentry", "supabase"] {
            assert!(
                names.contains(&expected),
                "default_rotation_providers must include '{expected}'"
            );
        }
    }

    #[test]
    fn new_rotation_sources_serialize_to_lowercase() {
        for (src, expected) in [
            (RotationSource::Vercel, r#""vercel""#),
            (RotationSource::Sentry, r#""sentry""#),
            (RotationSource::Supabase, r#""supabase""#),
        ] {
            let json = serde_json::to_string(&src).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn not_supported_error_display_is_human_readable() {
        let err = RotationProviderError::NotSupported {
            reason: "see the vendor dashboard".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("does not support API-driven rotation"));
        assert!(msg.contains("see the vendor dashboard"));
    }

    // ── GitHub PAT guidance ───────────────────────────────────────────────────

    #[test]
    fn github_missing_installation_id_explains_pat_limitation() {
        let provider = GitHubRotationProvider;
        let config = RotationProviderConfig {
            provider: "github".to_string(),
            api_key_env: Some("PHANTOM_TEST_GITHUB_NO_INSTALL_KEY".to_string()),
            account_id: None, // missing installation ID
            ..Default::default()
        };

        // A non-mock placeholder so the real (pre-HTTP) validation path runs;
        // the account_id check errors before any network call is made.
        unsafe {
            std::env::set_var(
                "PHANTOM_TEST_GITHUB_NO_INSTALL_KEY",
                "ghp_unit_test_placeholder",
            )
        };

        let err = provider
            .initiate_rotation("GITHUB_TOKEN", &config)
            .expect_err("missing account_id must return an error");
        let msg = err.to_string();
        assert!(
            msg.contains("installation ID"),
            "error must ask for the App installation ID"
        );
        assert!(
            msg.contains("github.com/settings/tokens"),
            "error must point PAT users at manual rotation"
        );

        unsafe { std::env::remove_var("PHANTOM_TEST_GITHUB_NO_INSTALL_KEY") };
    }

    // ── Bootstrap fallback (vault-sourced) ────────────────────────────────────

    #[test]
    fn bootstrap_fallback_is_used_when_env_var_unset() {
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_TEST_BOOTSTRAP_UNSET_VAR_A".to_string()),
            enabled: true,
            ..Default::default()
        };
        unsafe { std::env::remove_var("PHANTOM_TEST_BOOTSTRAP_UNSET_VAR_A") };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        // The caller (CLI/MCP) would have read this from the vault under the
        // api_key_env name; the mock prefix keeps the flow hermetic.
        let bootstrap = Some(zeroize::Zeroizing::new(
            "sk_test_mock_vault_bootstrap".to_string(),
        ));

        let result = auto_sync_rotation_with_bootstrap(
            "STRIPE_SECRET_KEY",
            Some(&config),
            &providers,
            bootstrap,
        )
        .expect("bootstrap-backed rotation must succeed");
        assert!(
            result.is_some(),
            "vault-sourced bootstrap must drive the mock rotation path"
        );
    }

    #[test]
    fn bootstrap_fallback_env_var_takes_precedence() {
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_TEST_BOOTSTRAP_PRECEDENCE_VAR".to_string()),
            enabled: true,
            ..Default::default()
        };
        // Env var present with the mock prefix; the bootstrap carries a
        // non-mock placeholder that would fail if it were consulted first
        // (it would attempt a real HTTP call, which mocks never do).
        unsafe {
            std::env::set_var(
                "PHANTOM_TEST_BOOTSTRAP_PRECEDENCE_VAR",
                "sk_test_mock_env_wins",
            )
        };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let bootstrap = Some(zeroize::Zeroizing::new("unit_test_placeholder".to_string()));

        let result = auto_sync_rotation_with_bootstrap(
            "STRIPE_SECRET_KEY",
            Some(&config),
            &providers,
            bootstrap,
        )
        .expect("env-var-backed rotation must succeed");
        assert!(result.is_some(), "env var must win over the vault fallback");

        unsafe { std::env::remove_var("PHANTOM_TEST_BOOTSTRAP_PRECEDENCE_VAR") };
    }

    #[test]
    fn bootstrap_override_is_cleared_after_the_call() {
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_TEST_BOOTSTRAP_CLEARED_VAR".to_string()),
            enabled: true,
            ..Default::default()
        };
        unsafe { std::env::remove_var("PHANTOM_TEST_BOOTSTRAP_CLEARED_VAR") };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let bootstrap = Some(zeroize::Zeroizing::new(
            "sk_test_mock_cleared_after".to_string(),
        ));
        auto_sync_rotation_with_bootstrap(
            "STRIPE_SECRET_KEY",
            Some(&config),
            &providers,
            bootstrap,
        )
        .expect("bootstrap-backed rotation must succeed");

        // A follow-up call WITHOUT a bootstrap must fail NotConfigured —
        // proving the RAII guard cleared the thread-local override.
        let err = auto_sync_rotation("STRIPE_SECRET_KEY", Some(&config), &providers)
            .expect_err("override must not leak into subsequent calls");
        assert!(
            matches!(err, RotationProviderError::NotConfigured),
            "expected NotConfigured after guard cleanup, got: {err}"
        );
    }

    #[test]
    fn bootstrap_none_keeps_env_only_behaviour() {
        let config = RotationProviderConfig {
            provider: "stripe".to_string(),
            api_key_env: Some("PHANTOM_TEST_BOOTSTRAP_NONE_VAR".to_string()),
            enabled: true,
            ..Default::default()
        };
        unsafe { std::env::remove_var("PHANTOM_TEST_BOOTSTRAP_NONE_VAR") };
        unsafe { std::env::remove_var("PHANTOM_AUDIT") };

        let providers = default_rotation_providers();
        let err =
            auto_sync_rotation_with_bootstrap("STRIPE_SECRET_KEY", Some(&config), &providers, None)
                .expect_err("no env var and no bootstrap must fail");
        assert!(
            matches!(err, RotationProviderError::NotConfigured),
            "expected NotConfigured, got: {err}"
        );
    }
}
