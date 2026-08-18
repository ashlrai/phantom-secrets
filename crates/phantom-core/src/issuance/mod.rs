//! Credential **issuance** — bootstrapping the durable ROOT credential that the
//! shipped [`crate::rotation_provider`] later renews from.
//!
//! Issuance is the *writer* of the `[phantom.secrets.<name>.rotation_provider]`
//! block; rotation is the *reader*. A [`ConsentEngine`] runs the ONE human
//! consent (a browser click, a device code) and returns the durable root(s) —
//! a GitHub App private-key PEM, an OAuth refresh token — inside
//! [`zeroize::Zeroizing`]. It never touches the vault: exactly like
//! `rotation_provider.rs`, the dependency direction is vault → core, so
//! `issue()` returns an [`IssuanceOutcome`] and the **CLI/MCP layer** performs
//! every `vault.store(...)`.
//!
//! # Security
//!
//! - Every root value is a [`zeroize::Zeroizing<String>`] end to end and is
//!   **never** logged, printed, returned to the model, emitted in `--json`, or
//!   carried in an MCP response. It travels vendor → core → CLI → vault only.
//! - [`IssuanceOutcome`] / [`IssuedMaterial`] carry a **redacting `Debug`**
//!   (values render as `[redacted]`), mirroring `AutoSyncOutcome`.
//! - Vendor error bodies only ever surface through
//!   [`crate::rotation_provider::summarize_error_body`] (type/code/status only).
//! - The mock fast-path is fail-closed: issuance against a non-production
//!   endpoint (the test wiremock server, reached via the `endpoints` override
//!   seam) requires the explicit `PHANTOM_ALLOW_MOCK_ISSUANCE=1` opt-in and is
//!   audit-tagged `grant.issuance.mock`, so a prompt-injected agent can never
//!   redirect a real issuance at an attacker-controlled host.

pub mod browser;
pub mod device;
pub mod endpoints;
pub mod github_app;
pub mod loopback;
pub mod pkce;

pub use browser::{BrowserOpener, NoBrowser};
pub use device::DeviceFlowEngine;
pub use endpoints::Endpoints;
pub use github_app::{mint_app_jwt, GithubAppManifestFlow, GithubManifestSpec};
pub use loopback::{
    CapturedCode, LoopbackBinding, LoopbackListener, MockLoopbackListener, StdLoopbackListener,
};
pub use pkce::LoopbackPkceEngine;

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
}

impl MaterialKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pem => "pem",
            Self::ClientId => "client-id",
            Self::ClientSecret => "client-secret",
            Self::RefreshToken => "refresh-token",
            Self::WebhookSecret => "webhook-secret",
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
    /// An endpoint override was not https-or-localhost (fail closed before I/O).
    InvalidEndpoint { var: String, value: String },
    /// Mock issuance attempted without the `PHANTOM_ALLOW_MOCK_ISSUANCE=1`
    /// opt-in (or `cfg(test)`). Fail closed.
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
            Self::InvalidEndpoint { var, value } => write!(
                f,
                "{var} must use https:// (or http://localhost / http://127.0.0.1 for local \
                 testing). Got: {value}"
            ),
            Self::MockDisabled => write!(
                f,
                "issuance endpoints are overridden to a non-production host, but mock issuance \
                 is disabled in this build. Mock issuance is for tests only; set \
                 PHANTOM_ALLOW_MOCK_ISSUANCE=1 to enable it in a test environment."
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
    ]
}

// ── Mock guard ──────────────────────────────────────────────────────────────

/// Returns `true` when mock issuance (issuing against a non-production endpoint,
/// i.e. a test wiremock server reached via the `endpoints` override seam) is
/// permitted.
///
/// Fail closed: mock issuance is allowed only under `cfg(test)` or with the
/// explicit `PHANTOM_ALLOW_MOCK_ISSUANCE=1` opt-in — never in a shipped binary
/// with a default environment. This is what stops a prompt-injected agent from
/// pointing issuance at an attacker-controlled host to capture a "root" it
/// planted.
pub fn issuance_mock_allowed() -> bool {
    cfg!(test)
        || std::env::var("PHANTOM_ALLOW_MOCK_ISSUANCE")
            .map(|v| v == "1")
            .unwrap_or(false)
}

/// Public alias for callers outside the crate (the CLI decides whether to
/// swap in the test harness listener). Same fail-closed semantics.
pub fn mock_issuance_enabled() -> bool {
    issuance_mock_allowed()
}

/// Build the blocking HTTP client used by the issuance engines. Lives in core
/// so the CLI need not depend on `reqwest` directly (it holds the value by
/// inference and passes `&client` into [`IssuanceDeps`]).
pub fn build_http_client() -> Result<reqwest::blocking::Client, IssuanceError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("phantom-secrets-issuance/0.1")
        .build()
        .map_err(|e| IssuanceError::Network {
            reason: format!("failed to build HTTP client: {e}"),
        })
}

/// Guard invoked by every engine when `deps.endpoints.overridden` is set:
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
        let outcome = IssuanceOutcome {
            provider: "github".to_string(),
            grant_type: GrantType::AppIdentity,
            materials: vec![IssuedMaterial {
                phm_name: "GITHUB_APP_PEM".to_string(),
                value: Zeroizing::new("-----BEGIN RSA PRIVATE KEY-----secret".to_string()),
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
