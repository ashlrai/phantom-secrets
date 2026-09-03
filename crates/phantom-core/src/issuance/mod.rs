//! Credential-issuance protocol foundations.
//!
//! This release hard-denies every [`ConsentEngine::issue`] before request
//! inspection, browser, loopback, environment, or network effects. The protocol
//! implementations execute only in crate-local tests against explicit
//! overridden endpoints. They are foundations for a future compensated
//! enrollment transaction, not evidence of live enrollment capability.
//!
//! # Security
//!
//! - Application-owned root buffers are [`zeroize::Zeroizing<String>`] and are
//!   **never** logged, printed, returned to the model, emitted in `--json`, or
//!   carried in an MCP response. It travels vendor → core → CLI → vault only.
//! - [`IssuanceOutcome`] / [`IssuedMaterial`] carry a **redacting `Debug`**
//!   (values render as `[redacted]`), mirroring `AutoSyncOutcome`.
//! - Vendor error bodies only ever surface through
//!   [`crate::rotation_provider::summarize_error_body`] (type/code/status only).
//! - Endpoint injection and protocol execution are available only to this
//!   crate's unit tests. Shipped builds return `NotSupported` first.

pub mod browser;
pub mod device;
pub mod endpoints;
pub mod github_app;
pub mod loopback;
pub mod pkce;
pub mod sentry;
pub mod stripe;
pub mod supabase;
pub mod vercel;

pub use browser::{BrowserOpener, NoBrowser};
pub use device::DeviceFlowEngine;
pub use endpoints::Endpoints;
pub use github_app::{mint_app_jwt, GithubAppManifestFlow, GithubManifestSpec};
#[cfg(test)]
pub use loopback::MockLoopbackListener;
pub use loopback::{CapturedCode, LoopbackBinding, LoopbackListener, StdLoopbackListener};
pub use pkce::LoopbackPkceEngine;
pub use sentry::{
    mint_install_jwt, SentryInstallFlow, SENTRY_APP_JWT_SEED_NAME, SENTRY_CLIENT_ID_NAME,
    SENTRY_ORG_TOKEN_NAME, SENTRY_ORG_TOKEN_TTL_SECS,
};
pub use stripe::{StripeAppOAuthFlow, StripeRestrictedKeyFlow, STRIPE_REFRESH_TOKEN_NAME};
pub use supabase::{SupabaseManagementProvider, SupabaseOAuthFlow, SUPABASE_REFRESH_TOKEN_NAME};
pub use vercel::{VercelIntegrationFlow, VERCEL_INTEGRATION_TOKEN_NAME};

use crate::rotation_provider::RotationProviderConfig;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

// ── Grant type ──────────────────────────────────────────────────────────────

/// The four grant shapes from `docs/grants-spec.md`. Issuance seeds #2/#3;
/// #1 (self-rotating) and #4 (manual) need no consent engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantType {
    /// The credential mints its own successor (Vercel).
    SelfRotating,
    /// The consent creates an identity; tokens are derived and disposable
    /// (GitHub App PEM → installation tokens).
    AppIdentity,
    /// The vendor gates minting behind a browser session; the refresh token is
    /// the root (Supabase, Sentry, GitHub user-to-server).
    OauthRefresh,
    /// No API to automate — the human rotates in a dashboard (Stripe et al.).
    Manual,
}

impl GrantType {
    /// Stable lowercase label for audit events and `--json`.
    pub fn label(self) -> &'static str {
        match self {
            Self::SelfRotating => "self-rotating",
            Self::AppIdentity => "app-identity",
            Self::OauthRefresh => "oauth-refresh",
            Self::Manual => "manual",
        }
    }
}

// ── Issued material ─────────────────────────────────────────────────────────

/// The class of a single issued secret, used only for operator-facing labels
/// and to decide the `sensitive` flag. Never affects redaction — every value
/// is redacted in `Debug` regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterialKind {
    /// RSA private key PEM (the perpetual GitHub App root).
    Pem,
    /// OAuth / App client id (non-sensitive, still vaulted for completeness).
    ClientId,
    /// OAuth / App client secret.
    ClientSecret,
    /// OAuth refresh token (the durable root of an oauth-refresh grant).
    RefreshToken,
    /// GitHub App webhook signing secret.
    WebhookSecret,
    /// A non-expiring access token that is itself the durable root — e.g. the
    /// team-scoped Vercel Integration token (app-identity grant, no refresh).
    AccessToken,
}

impl MaterialKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pem => "pem",
            Self::ClientId => "client-id",
            Self::ClientSecret => "client-secret",
            Self::RefreshToken => "refresh-token",
            Self::WebhookSecret => "webhook-secret",
            Self::AccessToken => "access-token",
        }
    }
}

/// One durable secret to be vaulted by the CLI/MCP caller. `phm_name` is the
/// `phm:` ref the vault stores under; `value` is the root credential and is
/// **never** rendered in full (redacting `Debug`).
pub struct IssuedMaterial {
    /// Vault key the value is stored under, e.g. `"GITHUB_APP_PEM"`.
    pub phm_name: String,
    /// The root credential — `Zeroizing`, never logged, never printed.
    pub value: Zeroizing<String>,
    /// The material class (for labels + `sensitive` derivation).
    pub kind: MaterialKind,
    /// `false` only for a client id; every other kind is `true`.
    pub sensitive: bool,
}

impl fmt::Debug for IssuedMaterial {
    /// Redacting `Debug`: the value is never rendered — only its name/kind.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedMaterial")
            .field("phm_name", &self.phm_name)
            .field("value", &"[redacted]")
            .field("kind", &self.kind)
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

// ── Metadata ────────────────────────────────────────────────────────────────

/// Non-secret facts safe for stdout / `--json`. **No token bytes ever.**
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssuanceMetadata {
    /// Human-facing app/grant name.
    pub display_name: String,
    /// Login / org, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// GitHub App id, when a GitHub App was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<u64>,
    /// GitHub App slug, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_slug: Option<String>,
    /// Discovered GitHub App installation ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub installation_ids: Vec<String>,
    /// OAuth scopes requested/granted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Refresh-token lifetime (unix seconds), if the vendor returns one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Human next-step notes (e.g. "Install the app: {url}").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

// ── Outcome ─────────────────────────────────────────────────────────────────

/// Result of a successful consent. Returned to the CLI/MCP layer, which does
/// ALL vault writes (core stays vault-free). Carries a redacting `Debug`.
pub struct IssuanceOutcome {
    /// Provider identity, e.g. `"github"` (the rotation-provider name).
    pub provider: String,
    /// The grant shape this consent produced.
    pub grant_type: GrantType,
    /// Roots to vault under their `phm:` names.
    pub materials: Vec<IssuedMaterial>,
    /// The `[rotation_provider]` block to write so `phantom rotate` works.
    pub rotation_config: RotationProviderConfig,
    /// Non-secret facts, safe to print.
    pub metadata: IssuanceMetadata,
}

impl fmt::Debug for IssuanceOutcome {
    /// Redacting `Debug`: `materials` render their names but never their values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuanceOutcome")
            .field("provider", &self.provider)
            .field("grant_type", &self.grant_type)
            .field("materials", &self.materials) // each already redacts its value
            .field("rotation_config", &self.rotation_config)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl IssuanceOutcome {
    /// The vaulted secret names, in order — the ONLY material identifiers ever
    /// emitted in `--json` (`vaulted: [...]`). Values are never included.
    pub fn vaulted_names(&self) -> Vec<String> {
        self.materials.iter().map(|m| m.phm_name.clone()).collect()
    }
}

// ── Error ───────────────────────────────────────────────────────────────────

/// Errors during a consent/issuance flow. No variant carries a secret value:
/// every `reason` that transits a vendor body is pre-passed through
/// [`crate::rotation_provider::summarize_error_body`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuanceError {
    /// The loopback/device consent never completed within the deadline.
    ConsentTimeout { waited_secs: u64 },
    /// The user declined, or the returned `state` failed the CSRF check.
    ConsentDenied,
    /// No usable browser (headless) — `fallback` names the recovery flow.
    BrowserUnavailable { fallback: &'static str },
    /// Could not bind the 127.0.0.1 loopback listener.
    LoopbackBindFailed { reason: String },
    /// A token/manifest exchange returned a non-2xx status.
    Exchange { status: u16, reason: String },
    /// Network error or timeout reaching the vendor.
    Network { reason: String },
    /// The vendor returned an unparseable / unexpected body.
    UnexpectedResponse { reason: String },
    /// This provider has no automatable consent engine.
    NotSupported { reason: String },
    /// Mock issuance attempted outside this crate's unit-test build.
    MockDisabled,
}

impl fmt::Display for IssuanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConsentTimeout { waited_secs } => write!(
                f,
                "consent was not completed within {waited_secs}s — retry with --flow device \
                 for a headless code-entry flow"
            ),
            Self::ConsentDenied => write!(
                f,
                "consent was denied or the returned state failed the CSRF check"
            ),
            Self::BrowserUnavailable { fallback } => {
                write!(f, "no browser available for this consent — {fallback}")
            }
            Self::LoopbackBindFailed { reason } => {
                write!(
                    f,
                    "failed to bind the 127.0.0.1 loopback listener: {reason}"
                )
            }
            Self::Exchange { status, reason } => {
                write!(f, "credential exchange failed (HTTP {status}): {reason}")
            }
            Self::Network { reason } => write!(f, "network error during issuance: {reason}"),
            Self::UnexpectedResponse { reason } => {
                write!(f, "unexpected response during issuance: {reason}")
            }
            Self::NotSupported { reason } => write!(f, "issuance not supported: {reason}"),
            Self::MockDisabled => write!(
                f,
                "issuance endpoints are overridden, but endpoint injection and mock issuance \
                 are compiled only for Phantom's unit tests"
            ),
        }
    }
}

impl std::error::Error for IssuanceError {}

// ── Request / deps / trait ──────────────────────────────────────────────────

/// Which OAuth consent flavour to run for a generic provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    /// RFC 8252 loopback + RFC 7636 S256.
    Pkce,
    /// RFC 8628 device authorization grant (headless).
    Device,
}

/// Everything a [`ConsentEngine`] needs to run one consent.
pub struct IssuanceRequest {
    /// Provider identity, e.g. `"github-app"`, `"supabase"`.
    pub provider: String,
    /// Existing OAuth/App client id (pkce/device against an existing app).
    pub client_id: Option<String>,
    /// The client secret, resolved from an env var by the caller — never disk.
    pub client_secret: Option<Zeroizing<String>>,
    /// Requested OAuth scopes.
    pub scopes: Vec<String>,
    /// CLI `--flow` override (pkce/device).
    pub flow: Option<FlowKind>,
    /// GitHub App manifest spec (github-app only).
    pub app_manifest: Option<GithubManifestSpec>,
    /// Vercel team id to scope the grant to (`vercel-integration` only). When
    /// `None`, the team is taken from the token-exchange response (`null` =
    /// personal account). Plumbed onto every subsequent team-scoped REST call.
    pub team_id: Option<String>,
    /// Stripe only: the target Stripe account id hint (`acct_…`) for
    /// `phantom grant add stripe --account`. Advisory — the authoritative
    /// account comes back as `stripe_user_id` in the token exchange.
    pub account: Option<String>,
    /// Supabase only: the `organization_slug` to pre-select on the OAuth
    /// consent page (`phantom grant add supabase --org <slug>`). Purely a UX
    /// hint — the user can still switch orgs in the browser — and it carries no
    /// secret. `None` shows the org picker.
    pub org: Option<String>,
}

/// Injected side-effects → makes core hermetically testable and cleanly handles
/// headless environments (fake browser / fake loopback in tests).
pub struct IssuanceDeps<'a> {
    /// Opens a URL in the user's browser (real impl lives in the CLI).
    pub browser: &'a dyn BrowserOpener,
    /// Binds the 127.0.0.1 loopback listener and captures the redirect.
    pub loopback: &'a dyn LoopbackListener,
    /// Blocking HTTP client (built by the caller, `reqwest::blocking`).
    pub http: &'a reqwest::blocking::Client,
    /// Prod URLs or test overrides.
    pub endpoints: &'a Endpoints,
}

/// A single provider's consent mechanic. Parallels
/// [`crate::rotation_provider::RotationProvider`].
pub trait ConsentEngine: Send + Sync {
    /// Engine name, e.g. `"github-app-manifest"`, `"loopback-pkce"`.
    fn name(&self) -> &str;

    /// The grant shape this engine produces.
    fn grant_type(&self) -> GrantType;

    /// Run the ONE human consent and return the durable root(s). Core performs
    /// no vault I/O. MUST NOT log/print any returned value; MUST zeroize every
    /// intermediate (code, code_verifier, client_secret) after the exchange.
    fn issue(
        &self,
        req: &IssuanceRequest,
        deps: &IssuanceDeps,
    ) -> Result<IssuanceOutcome, IssuanceError>;
}

/// The consent engines Phantom ships. Selected by the CLI from the provider +
/// `--flow`; dispatch is by identity, never a secret-name heuristic.
pub fn default_consent_engines() -> Vec<Box<dyn ConsentEngine>> {
    vec![
        Box::new(GithubAppManifestFlow),
        Box::new(LoopbackPkceEngine),
        Box::new(DeviceFlowEngine),
        Box::new(VercelIntegrationFlow),
        Box::new(StripeAppOAuthFlow),
        Box::new(StripeRestrictedKeyFlow),
        Box::new(SupabaseOAuthFlow),
        Box::new(SentryInstallFlow),
    ]
}

// ── Mock guard ──────────────────────────────────────────────────────────────

/// Returns `true` when mock issuance (issuing against a non-production endpoint,
/// i.e. a test wiremock server reached via the `endpoints` override seam) is
/// permitted.
///
/// Fail closed: mock issuance is allowed only under `cfg(test)`. Shipped
/// libraries contain no environment-variable escape hatch.
pub fn issuance_mock_allowed() -> bool {
    cfg!(test)
}

/// Admit only crate-local, overridden-endpoint issuance tests.
///
/// Shipped library builds hard-deny every consent engine before request
/// inspection or browser, loopback, environment, and network effects. Unit
/// tests may exercise the protocol foundations only through the explicit
/// endpoint-override seam, which is unavailable to downstream builds.
pub(crate) fn guard_test_only_issuance(deps: &IssuanceDeps<'_>) -> Result<(), IssuanceError> {
    if !issuance_mock_allowed() || !deps.endpoints.is_overridden() {
        return Err(IssuanceError::NotSupported {
            reason: "live credential enrollment is disabled in this release until a durable compensated persistence and recovery transaction exists; obtain the credential at the provider and store it from a trusted terminal"
                .to_string(),
        });
    }
    guard_mock_issuance()
}

/// Build the blocking HTTP client used by the issuance engines. Lives in core
/// so the CLI need not depend on `reqwest` directly (it holds the value by
/// inference and passes `&client` into [`IssuanceDeps`]).
pub fn build_http_client() -> Result<reqwest::blocking::Client, IssuanceError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("phantom-secrets-issuance/0.1")
        // RFC 9700 (OAuth 2.0 Security BCP): the token/exchange endpoint MUST NOT
        // follow redirects. reqwest strips sensitive *headers* on cross-host
        // redirects but re-sends the POST *body* on 307/308 — which here carries
        // the authorization `code` + PKCE `code_verifier`, `client_secret`, or
        // `device_code`. Disabling redirects means any 3xx from the token
        // endpoint surfaces as a non-2xx response through the existing error
        // path instead of replaying those secrets to the redirect target.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| IssuanceError::Network {
            reason: format!("failed to build HTTP client: {e}"),
        })
}

/// Guard invoked by every engine when unit tests inject overridden endpoints:
/// permits the mock branch (tagging the audit log with a distinct
/// `grant.issuance.mock` event) or fails closed.
pub(crate) fn guard_mock_issuance() -> Result<(), IssuanceError> {
    if issuance_mock_allowed() {
        crate::audit::log("grant.issuance.mock", None);
        Ok(())
    } else {
        Err(IssuanceError::MockDisabled)
    }
}

/// 32 random bytes, base64url — the CSRF `state` shared by the loopback engines.
pub(crate) fn random_state() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_debug_redacts_material_values() {
        // Assembled at runtime so no literal `BEGIN … PRIVATE KEY` header is
        // committed; the value still carries the marker so the leak assertion
        // below is meaningful.
        let label = "RSA PRIVATE KEY";
        let secret_pem = format!("-----BEGIN {label}-----secret");
        let outcome = IssuanceOutcome {
            provider: "github".to_string(),
            grant_type: GrantType::AppIdentity,
            materials: vec![IssuedMaterial {
                phm_name: "GITHUB_APP_PEM".to_string(),
                value: Zeroizing::new(secret_pem),
                kind: MaterialKind::Pem,
                sensitive: true,
            }],
            rotation_config: RotationProviderConfig {
                provider: "github".to_string(),
                ..Default::default()
            },
            metadata: IssuanceMetadata::default(),
        };
        let rendered = format!("{outcome:?}");
        assert!(
            rendered.contains("[redacted]"),
            "value must be redacted: {rendered}"
        );
        assert!(
            !rendered.contains("BEGIN RSA PRIVATE KEY"),
            "PEM leaked into Debug: {rendered}"
        );
        // Non-secret metadata (the name) is still visible for diagnostics.
        assert!(rendered.contains("GITHUB_APP_PEM"));
    }

    #[test]
    fn vaulted_names_lists_only_names() {
        let outcome = IssuanceOutcome {
            provider: "github".to_string(),
            grant_type: GrantType::AppIdentity,
            materials: vec![
                IssuedMaterial {
                    phm_name: "GITHUB_APP_PEM".to_string(),
                    value: Zeroizing::new("x".to_string()),
                    kind: MaterialKind::Pem,
                    sensitive: true,
                },
                IssuedMaterial {
                    phm_name: "GITHUB_APP_CLIENT_ID".to_string(),
                    value: Zeroizing::new("y".to_string()),
                    kind: MaterialKind::ClientId,
                    sensitive: false,
                },
            ],
            rotation_config: RotationProviderConfig::default(),
            metadata: IssuanceMetadata::default(),
        };
        assert_eq!(
            outcome.vaulted_names(),
            vec![
                "GITHUB_APP_PEM".to_string(),
                "GITHUB_APP_CLIENT_ID".to_string()
            ]
        );
    }
}
