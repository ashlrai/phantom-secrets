//! Supabase OAuth grant + self-rotating Management-API issuer.
//!
//! Two halves, matching the grants-spec "one consent, perpetual lifecycle":
//!
//! 1. [`SupabaseOAuthFlow`] — the ONE human "Authorize" click. Authorization
//!    Code + **PKCE S256** with a `127.0.0.1` loopback redirect, exactly like
//!    [`super::pkce::LoopbackPkceEngine`], but with the two Supabase-specific
//!    twists the generic engine cannot express:
//!    - the token exchange authenticates the **confidential client with HTTP
//!      Basic auth** (`Authorization: Basic base64(client_id:client_secret)`),
//!      never client credentials in the form body;
//!    - the authorize URL carries an optional `organization_slug` to pre-select
//!      the org on the consent page (`phantom grant add supabase --org <slug>`).
//!    - the durable root is the **refresh token** (returned only via
//!      [`IssuanceOutcome`] for the CLI to vault — never logged, printed, in
//!      `--json`, or in an MCP response).
//!
//! 2. [`SupabaseManagementProvider`] — the perpetual half, a
//!    [`RotationProvider`] with a distinct identity (`"supabase-management"`,
//!    NOT the manual-only `"supabase"` PAT provider). Two trait-coherent modes,
//!    dispatched by whether `account_id` names a project ref:
//!    - **management-token self-rotation** (`account_id` = `None`): calls the
//!      Supabase refresh grant (`grant_type=refresh_token`, Basic client auth)
//!      and returns the **new** refresh token. Supabase rotates the refresh
//!      token on every use, so this is *atomic self-rotation* — the caller
//!      persists the returned successor before the predecessor is spent, exactly
//!      the Vercel store-then-invalidate ordering.
//!    - **project-API-key minting** (`account_id` = a project ref): mints a
//!      fresh `sb_secret_` key via `POST /v1/projects/{ref}/api-keys`, returns
//!      it, and best-effort DELETEs the rotated-out key in
//!      [`post_store_cleanup`](RotationProvider::post_store_cleanup). The
//!      bootstrap here is a **management access token** the operator keeps fresh
//!      (via the self-rotation above) — the same "freshly-minted bootstrap per
//!      rotation" contract as the GitHub App JWT provider.
//!
//! # Security
//!
//! - Every token (refresh, access, minted `sb_secret_`) is a [`Zeroizing`]
//!   end to end; none is ever logged, printed, or surfaced in an error/JSON.
//! - Vendor error bodies pass through
//!   [`crate::rotation_provider::summarize_error_body`] (type/code/status only).
//! - The HTTP client is the issuance client with `redirect(Policy::none())`;
//!   the rotation client is the shared rotation client. A `401` on refresh is
//!   surfaced as "the user revoked the app" — never a silent demotion.
//! - The Management-API base can be pointed at a wiremock server ONLY when mock
//!   rotation is enabled (`cfg(test)` or `PHANTOM_ALLOW_MOCK_ROTATION=1`) and
//!   only over https/localhost, so a prompt-injected agent can never redirect a
//!   real rotation at an attacker host.

use serde_json::Value;
use zeroize::Zeroizing;

use super::pkce::{
    build_authorize_url, code_challenge_s256, generate_code_verifier, map_oauth_error, now_unix,
};
use super::{
    guard_mock_issuance, random_state, ConsentEngine, GrantType, IssuanceDeps, IssuanceError,
    IssuanceMetadata, IssuanceOutcome, IssuanceRequest, IssuedMaterial, MaterialKind,
};
use crate::rotation_provider::{
    build_http_client, decode_challenge_payload, encode_challenge_payload, guard_mock_rotation,
    mock_rotation_allowed, redact_challenge_id, resolve_api_key, summarize_error_body,
    RotationProvider, RotationProviderConfig, RotationProviderError, RotationSource,
};

// ── Constants ────────────────────────────────────────────────────────────────

/// Vault name the durable refresh-token root is stored under. Contains
/// `SUPABASE` + `REFRESH_TOKEN` so operators recognise it and so
/// `phantom rotate --name SUPABASE_REFRESH_TOKEN` locates the self-rotation.
pub const SUPABASE_REFRESH_TOKEN_NAME: &str = "SUPABASE_REFRESH_TOKEN";

/// The rotation-provider identity written into the `rotation_provider` block —
/// distinct from the manual-only `"supabase"` PAT provider.
pub const SUPABASE_MANAGEMENT_PROVIDER: &str = "supabase-management";

/// Env var holding the Supabase OAuth app **client id** used for Basic client
/// auth on the refresh grant (public value, but read from env for symmetry).
pub const ENV_SUPABASE_CLIENT_ID: &str = "SUPABASE_OAUTH_CLIENT_ID";
/// Env var holding the Supabase OAuth app **client secret** for Basic client
/// auth. Never read from disk; resolved from the process env only.
pub const ENV_SUPABASE_CLIENT_SECRET: &str = "SUPABASE_OAUTH_CLIENT_SECRET";

/// Gated override of the Management-API base (`https://api.supabase.com`) for
/// hermetic tests. Honoured only when mock rotation is enabled AND the value is
/// https-or-localhost.
pub const ENV_SUPABASE_API_BASE: &str = "PHANTOM_SUPABASE_API_BASE";

/// Production Management-API / OAuth base.
const DEFAULT_API_BASE: &str = "https://api.supabase.com";

/// Bootstrap values with this prefix take the hermetic mock fast-path (guarded
/// by [`mock_rotation_allowed`]); real bootstraps never start with it.
const MOCK_BOOTSTRAP_PREFIX: &str = "sbmock_";

/// Consent window for the browser "Authorize" click (matches the other engines).
const CONSENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

// ── Consent engine ───────────────────────────────────────────────────────────

/// The Supabase OAuth consent engine (grant type `OauthRefresh`).
///
/// Unit struct: all state is in the injected [`IssuanceDeps`].
pub struct SupabaseOAuthFlow;

impl ConsentEngine for SupabaseOAuthFlow {
    fn name(&self) -> &str {
        "supabase-oauth"
    }

    fn grant_type(&self) -> GrantType {
        GrantType::OauthRefresh
    }

    fn issue(
        &self,
        req: &IssuanceRequest,
        deps: &IssuanceDeps,
    ) -> Result<IssuanceOutcome, IssuanceError> {
        // Fail closed on overridden (non-production) endpoints unless mock
        // issuance is explicitly enabled — stops a prompt-injected agent from
        // redirecting the exchange (and the refresh token) to an attacker host.
        if deps.endpoints.overridden {
            guard_mock_issuance()?;
        }

        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| IssuanceError::NotSupported {
                reason: "supabase requires --client-id (the OAuth app's client id)".to_string(),
            })?;
        // Supabase OAuth apps are confidential clients: the token exchange is
        // authenticated with Basic auth, so the secret is mandatory.
        let client_secret =
            req.client_secret
                .as_ref()
                .ok_or_else(|| IssuanceError::NotSupported {
                    reason:
                        "supabase is a confidential client — pass --client-secret-env naming an \
                         env var that holds the OAuth app client secret"
                            .to_string(),
                })?;
        if deps.endpoints.authorize.is_empty() || deps.endpoints.token.is_empty() {
            return Err(IssuanceError::NotSupported {
                reason: "no authorize/token endpoint known for supabase; set the PHANTOM_OAUTH_* \
                         overrides"
                    .to_string(),
            });
        }

        // ── PKCE (S256 only — Supabase rejects `plain`) ──────────────────────
        let code_verifier = generate_code_verifier();
        let code_challenge = code_challenge_s256(&code_verifier);
        let state = random_state();

        // ── Loopback listener on 127.0.0.1:0 (RFC 8252 §7.3) ─────────────────
        let binding = deps.loopback.bind()?;

        // ── Authorize URL (+ organization_slug pre-select) ───────────────────
        let scope = req.scopes.join(" ");
        let mut params: Vec<(&str, &str)> = vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", &binding.redirect_uri),
            ("state", &state),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", &scope),
        ];
        if let Some(org) = req.org.as_deref() {
            // Non-secret UX hint; empty values are skipped by build_authorize_url.
            params.push(("organization_slug", org));
        }
        let authorize_url = build_authorize_url(&deps.endpoints.authorize, &params);
        deps.browser.open(&authorize_url);
        // Exactly ONE consent artifact to stderr (carries state/challenge, no secret).
        eprintln!("{authorize_url}");

        // ── Capture the redirect + verify CSRF state ─────────────────────────
        let captured = deps.loopback.wait(&state, None, CONSENT_TIMEOUT)?;
        if captured.state != state {
            return Err(IssuanceError::ConsentDenied);
        }

        // ── Exchange the code (+ verifier) with Basic client auth ────────────
        let response = deps
            .http
            .post(&deps.endpoints.token)
            .header("Accept", "application/json")
            .header("Authorization", basic_auth_header(client_id, client_secret))
            .header("User-Agent", "phantom-secrets/0.1")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", captured.code.as_str()),
                ("redirect_uri", binding.redirect_uri.as_str()),
                ("code_verifier", code_verifier.as_str()),
            ])
            .send()
            .map_err(|e| IssuanceError::Network {
                reason: e.to_string(),
            })?;

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            let body = response.text().unwrap_or_default();
            return Err(IssuanceError::Exchange {
                status,
                reason: summarize_error_body(&body),
            });
        }
        let body: Value = response
            .json()
            .map_err(|e| IssuanceError::UnexpectedResponse {
                reason: e.to_string(),
            })?;
        if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
            return Err(map_oauth_error(err, status));
        }

        build_supabase_outcome(&req.scopes, req.org.as_deref(), &body)
    }
}

/// Build the `OauthRefresh` outcome from the Supabase token response. The
/// refresh token is the durable root; the access token / expiries are metadata
/// only. The `rotation_provider` block dispatches to
/// [`SupabaseManagementProvider`] (self-rotation, no `account_id`).
fn build_supabase_outcome(
    scopes: &[String],
    org: Option<&str>,
    body: &Value,
) -> Result<IssuanceOutcome, IssuanceError> {
    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::UnexpectedResponse {
            reason: "supabase token response has no refresh_token — the OAuth app must be \
                     configured to issue a refresh token"
                .to_string(),
        })?;
    let refresh_token = Zeroizing::new(refresh_token.to_string());

    // Access-token lifetime is metadata only (never token bytes). Supabase
    // returns `expires_in` for the access token; a refresh-token TTL, when the
    // vendor sends one, takes precedence.
    let expires_at = body
        .get("refresh_token_expires_in")
        .or_else(|| body.get("expires_in"))
        .and_then(|v| v.as_u64())
        .map(|secs| now_unix().saturating_add(secs));

    let material = IssuedMaterial {
        phm_name: SUPABASE_REFRESH_TOKEN_NAME.to_string(),
        value: refresh_token,
        kind: MaterialKind::RefreshToken,
        sensitive: true,
    };
    let rotation_config = RotationProviderConfig {
        provider: SUPABASE_MANAGEMENT_PROVIDER.to_string(),
        api_key_env: Some(SUPABASE_REFRESH_TOKEN_NAME.to_string()),
        // No account_id → management-token self-rotation mode. A separate block
        // with account_id = <project ref> drives project-API-key minting.
        account_id: None,
        enabled: true,
        ..Default::default()
    };
    let metadata = IssuanceMetadata {
        display_name: "supabase".to_string(),
        account: org.map(|s| s.to_string()),
        scopes: scopes.to_vec(),
        expires_at,
        notes: vec![
            "`phantom rotate --name SUPABASE_REFRESH_TOKEN` refreshes the management token \
             (atomic — the successor is vaulted before the old one is spent)."
                .to_string(),
        ],
        ..Default::default()
    };

    Ok(IssuanceOutcome {
        provider: "supabase".to_string(),
        grant_type: GrantType::OauthRefresh,
        materials: vec![material],
        rotation_config,
        metadata,
    })
}

/// `Authorization: Basic base64(client_id:client_secret)`. The intermediate
/// `id:secret` string is held in `Zeroizing`; the returned header value still
/// carries the secret (base64), so it is passed straight into the request and
/// never logged.
fn basic_auth_header(client_id: &str, client_secret: &Zeroizing<String>) -> String {
    use base64::Engine as _;
    let creds = Zeroizing::new(format!("{client_id}:{}", client_secret.as_str()));
    let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
    format!("Basic {encoded}")
}

// ── Management-API rotation provider ─────────────────────────────────────────

/// Self-rotating Supabase Management-API issuer. See the module docs for the
/// two modes. Registered in
/// [`crate::rotation_provider::default_rotation_providers`] under the identity
/// `"supabase-management"`.
pub struct SupabaseManagementProvider;

impl RotationProvider for SupabaseManagementProvider {
    fn name(&self) -> &str {
        SUPABASE_MANAGEMENT_PROVIDER
    }

    fn matches(&self, secret_name: &str) -> bool {
        // Heuristic hint only (labels/doctor); dispatch is always by identity.
        let upper = secret_name.to_uppercase();
        upper.contains("SUPABASE")
            && (upper.contains("REFRESH")
                || upper.contains("PROJECT")
                || upper.contains("SECRET")
                || upper.contains("KEY")
                || upper.contains("TOKEN"))
    }

    fn initiate_rotation(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
    ) -> Result<String, RotationProviderError> {
        let bootstrap = resolve_api_key(config)?;

        // Hermetic mock fast-path (guarded — fails closed off cfg(test)).
        if bootstrap.starts_with(MOCK_BOOTSTRAP_PREFIX) {
            guard_mock_rotation(secret_name)?;
            return Ok(format!("mock_challenge_supabase_{secret_name}"));
        }

        match config.account_id.as_deref() {
            // Mode A: management-token self-rotation. The rotated secret IS the
            // refresh token; Supabase returns a new one on every refresh.
            None => {
                let (_access, new_refresh) = refresh_management_token(config, &bootstrap)?;
                Ok(encode_challenge_payload(new_refresh.as_str()))
            }
            // Mode B: mint a fresh project API key. The bootstrap is a management
            // ACCESS token the operator keeps fresh via Mode A (same
            // freshly-minted-bootstrap contract as the GitHub App JWT provider).
            Some(project_ref) => {
                let new_key = mint_project_api_key(config, &bootstrap, project_ref, secret_name)?;
                Ok(encode_challenge_payload(new_key.as_str()))
            }
        }
    }

    fn finalize_rotation(
        &self,
        challenge_id: &str,
        _config: &RotationProviderConfig,
    ) -> Result<Zeroizing<String>, RotationProviderError> {
        if challenge_id.starts_with("mock_challenge_supabase_") {
            if !mock_rotation_allowed() {
                return Err(RotationProviderError::ChallengeExpired {
                    challenge_id: redact_challenge_id(challenge_id),
                });
            }
            return Ok(Zeroizing::new("sb_secret_rotated_mock_value".to_string()));
        }
        decode_challenge_payload(challenge_id)
    }

    /// Best-effort deletion of the rotated-out project key (Mode B only), run by
    /// the caller only AFTER the successor is durably vaulted. Fail-open and
    /// audited (name only). Mode A (refresh) has no vendor-side delete.
    fn post_store_cleanup(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
        old_value: Option<&Zeroizing<String>>,
    ) -> Result<(), RotationProviderError> {
        let Some(project_ref) = config.account_id.as_deref() else {
            return Ok(()); // Mode A: nothing to revoke.
        };
        let Some(old) = old_value else {
            crate::audit::log("vault.rotation.old_token_revoke_skipped", Some(secret_name));
            return Ok(());
        };
        // Mock / rotated-mock values never reach the network.
        if old.starts_with(MOCK_BOOTSTRAP_PREFIX) || old.starts_with("sb_secret_rotated_mock") {
            return Ok(());
        }
        let Ok(access_token) = resolve_api_key(config) else {
            crate::audit::log("vault.rotation.old_token_revoke_failed", Some(secret_name));
            return Ok(());
        };
        if delete_matching_project_key(config, &access_token, project_ref, old).is_err() {
            crate::audit::log("vault.rotation.old_token_revoke_failed", Some(secret_name));
        }
        Ok(())
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Custom {
            provider_name: SUPABASE_MANAGEMENT_PROVIDER.to_string(),
        }
    }
}

/// Refresh the management token via `POST /v1/oauth/token`
/// (`grant_type=refresh_token`, Basic client auth). Returns
/// `(access_token, new_refresh_token)`, both `Zeroizing`. The new refresh token
/// MUST be persisted by the caller before the old one is considered spent.
///
/// `pub(crate)` so higher layers can compose "refresh → mint" explicitly.
pub(crate) fn refresh_management_token(
    config: &RotationProviderConfig,
    refresh_token: &Zeroizing<String>,
) -> Result<(Zeroizing<String>, Zeroizing<String>), RotationProviderError> {
    let client_id =
        std::env::var(ENV_SUPABASE_CLIENT_ID).map_err(|_| RotationProviderError::AuthFailed {
            reason: format!(
                "{ENV_SUPABASE_CLIENT_ID} must be set to the Supabase OAuth app client id to \
                 refresh the management token"
            ),
        })?;
    let client_secret =
        Zeroizing::new(std::env::var(ENV_SUPABASE_CLIENT_SECRET).map_err(|_| {
            RotationProviderError::AuthFailed {
                reason: format!(
                "{ENV_SUPABASE_CLIENT_SECRET} must be set to the Supabase OAuth app client secret"
            ),
            }
        })?);

    let base = supabase_api_base();
    let url = format!("{base}/v1/oauth/token");
    let client = build_http_client(config.timeout_secs)?;
    let response = client
        .post(&url)
        .header("Accept", "application/json")
        .header(
            "Authorization",
            basic_auth_header(&client_id, &client_secret),
        )
        .header("User-Agent", "phantom-secrets-rotation/0.1")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .map_err(|e| RotationProviderError::NetworkError {
            reason: e.to_string(),
        })?;

    let status = response.status().as_u16();
    if status == 401 {
        // No silent demotion: a 401 means the user disconnected the app / the
        // refresh token was revoked — the grant is broken and needs one consent.
        return Err(RotationProviderError::AuthFailed {
            reason: "Supabase refused the refresh token (HTTP 401) — the OAuth app was likely \
                     disconnected; re-run `phantom grant add supabase`"
                .to_string(),
        });
    }
    if !(200..300).contains(&status) {
        let body = response.text().unwrap_or_default();
        return Err(RotationProviderError::ApiError {
            status,
            reason: summarize_error_body(&body),
        });
    }

    let body: Value = response
        .json()
        .map_err(|e| RotationProviderError::UnexpectedResponse {
            reason: e.to_string(),
        })?;
    let access = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RotationProviderError::UnexpectedResponse {
            reason: "supabase refresh response missing access_token".to_string(),
        })?;
    let new_refresh = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RotationProviderError::UnexpectedResponse {
            reason: "supabase refresh response missing the rotated refresh_token".to_string(),
        })?;
    Ok((
        Zeroizing::new(access.to_string()),
        Zeroizing::new(new_refresh.to_string()),
    ))
}

/// Mint a fresh `sb_secret_` project API key via
/// `POST /v1/projects/{ref}/api-keys` with the management access token. Returns
/// the new key (`Zeroizing`). `pub(crate)` for explicit composition/testing.
pub(crate) fn mint_project_api_key(
    config: &RotationProviderConfig,
    access_token: &Zeroizing<String>,
    project_ref: &str,
    secret_name: &str,
) -> Result<Zeroizing<String>, RotationProviderError> {
    let base = supabase_api_base();
    let url = format!("{base}/v1/projects/{project_ref}/api-keys");
    let client = build_http_client(config.timeout_secs)?;
    let key_name = format!("phantom-{}-{}", secret_name.to_lowercase(), now_unix());

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", access_token.as_str()))
        .header("Content-Type", "application/json")
        .header("User-Agent", "phantom-secrets-rotation/0.1")
        .json(&serde_json::json!({ "type": "secret", "name": key_name }))
        .send()
        .map_err(|e| RotationProviderError::NetworkError {
            reason: e.to_string(),
        })?;

    let status = response.status().as_u16();
    if status == 401 || status == 403 {
        return Err(RotationProviderError::AuthFailed {
            reason: format!(
                "Supabase Management API returned HTTP {status} minting a project key — the \
                 management access token is invalid or lacks secrets:write (refresh it via \
                 `phantom rotate --name SUPABASE_REFRESH_TOKEN`)"
            ),
        });
    }
    if !(200..300).contains(&status) {
        let body = response.text().unwrap_or_default();
        return Err(RotationProviderError::ApiError {
            status,
            reason: summarize_error_body(&body),
        });
    }

    let body: Value = response
        .json()
        .map_err(|e| RotationProviderError::UnexpectedResponse {
            reason: e.to_string(),
        })?;
    let api_key = body
        .get("api_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RotationProviderError::UnexpectedResponse {
            reason: "supabase api-key response missing 'api_key'".to_string(),
        })?;
    if api_key.is_empty() {
        return Err(RotationProviderError::UnexpectedResponse {
            reason: "supabase returned an empty api_key".to_string(),
        });
    }
    Ok(Zeroizing::new(api_key.to_string()))
}

/// Best-effort: list the project's api-keys (revealed), find the one whose value
/// equals `old_value`, and DELETE it by id. Fail-open — any error propagates to
/// the caller which audits and moves on.
fn delete_matching_project_key(
    config: &RotationProviderConfig,
    access_token: &Zeroizing<String>,
    project_ref: &str,
    old_value: &Zeroizing<String>,
) -> Result<(), RotationProviderError> {
    let base = supabase_api_base();
    let client = build_http_client(config.timeout_secs)?;
    let list = client
        .get(format!(
            "{base}/v1/projects/{project_ref}/api-keys?reveal=true"
        ))
        .header("Authorization", format!("Bearer {}", access_token.as_str()))
        .header("User-Agent", "phantom-secrets-rotation/0.1")
        .send()
        .map_err(|e| RotationProviderError::NetworkError {
            reason: e.to_string(),
        })?;
    if !list.status().is_success() {
        return Err(RotationProviderError::ApiError {
            status: list.status().as_u16(),
            reason: "listing project api-keys failed".to_string(),
        });
    }
    let keys: Value = list
        .json()
        .map_err(|e| RotationProviderError::UnexpectedResponse {
            reason: e.to_string(),
        })?;
    let id = keys.as_array().and_then(|arr| {
        arr.iter()
            .find(|k| k.get("api_key").and_then(|v| v.as_str()) == Some(old_value.as_str()))
            .and_then(|k| k.get("id").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
    });
    let Some(id) = id else {
        // The old key is already gone (or was never a project key) — nothing to do.
        return Ok(());
    };
    let del = client
        .delete(format!("{base}/v1/projects/{project_ref}/api-keys/{id}"))
        .header("Authorization", format!("Bearer {}", access_token.as_str()))
        .header("User-Agent", "phantom-secrets-rotation/0.1")
        .send()
        .map_err(|e| RotationProviderError::NetworkError {
            reason: e.to_string(),
        })?;
    if !del.status().is_success() {
        return Err(RotationProviderError::ApiError {
            status: del.status().as_u16(),
            reason: "deleting rotated-out project api-key failed".to_string(),
        });
    }
    Ok(())
}

/// Resolve the Management-API base: production by default; a gated override for
/// hermetic tests (honoured only when mock rotation is enabled AND the value is
/// https-or-localhost, so a real rotation can never be redirected).
fn supabase_api_base() -> String {
    if let Ok(value) = std::env::var(ENV_SUPABASE_API_BASE) {
        if !value.is_empty() && is_https_or_localhost(&value) && mock_rotation_allowed() {
            return value.trim_end_matches('/').to_string();
        }
    }
    DEFAULT_API_BASE.to_string()
}

/// Accept only `https://…`, `http://localhost…`, or `http://127.0.0.1…`
/// (mirrors the issuance endpoint validator, including the host-confusion guard).
fn is_https_or_localhost(url: &str) -> bool {
    url.starts_with("https://")
        || url == "http://localhost"
        || url.starts_with("http://localhost/")
        || url.starts_with("http://localhost:")
        || url == "http://127.0.0.1"
        || url.starts_with("http://127.0.0.1/")
        || url.starts_with("http://127.0.0.1:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuance::browser::BrowserOpener;
    use crate::issuance::endpoints::Endpoints;
    use crate::issuance::loopback::{MockLoopbackListener, MockStateMode};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Serialize any test that touches process-wide env or the ambient audit log
    /// (mock guards emit audit events). Poison-tolerant per the repo convention.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    struct CapturingBrowser {
        urls: Mutex<Vec<String>>,
    }
    impl BrowserOpener for CapturingBrowser {
        fn open(&self, url: &str) -> bool {
            self.urls.lock().unwrap().push(url.to_string());
            true
        }
    }

    /// Dependency-free single-response HTTP stub on 127.0.0.1:0. Records the raw
    /// request text so tests can assert what was sent, then closes.
    fn spawn_stub(status: u16, body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen_c = seen.clone();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                seen_c
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        (base, seen)
    }

    fn endpoints(token: String) -> Endpoints {
        Endpoints {
            github_web: String::new(),
            github_api: String::new(),
            authorize: "https://api.supabase.com/v1/oauth/authorize".to_string(),
            token,
            device_code: String::new(),
            overridden: true, // exercises the mock gate (allowed under cfg(test))
        }
    }

    fn request(org: Option<&str>) -> IssuanceRequest {
        IssuanceRequest {
            provider: "supabase".to_string(),
            client_id: Some("sb_client_id".to_string()),
            client_secret: Some(Zeroizing::new("sb_client_secret_MOCK".to_string())),
            scopes: vec!["projects:read".to_string(), "secrets:write".to_string()],
            flow: None,
            app_manifest: None,
            team_id: None,
            account: None,
            org: org.map(|s| s.to_string()),
        }
    }

    // ── Consent engine ───────────────────────────────────────────────────────

    #[test]
    fn oauth_flow_yields_refresh_root_uses_basic_auth_and_org_preselect() {
        let _g = env_guard();
        let (base, seen) = spawn_stub(
            200,
            r#"{"access_token":"sbat_access_MOCK","refresh_token":"sbrt_refresh_MOCK","expires_in":86400}"#,
        );
        let http = crate::issuance::build_http_client().unwrap();
        let ep = endpoints(format!("{base}/v1/oauth/token"));
        let browser = CapturingBrowser {
            urls: Mutex::new(Vec::new()),
        };
        let loopback = MockLoopbackListener::new("auth_code_supa", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let outcome = SupabaseOAuthFlow
            .issue(&request(Some("ashlrai")), &deps)
            .unwrap();

        // Durable root = the refresh token, vaulted under the fixed name.
        assert_eq!(outcome.materials.len(), 1);
        let m = &outcome.materials[0];
        assert_eq!(m.phm_name, SUPABASE_REFRESH_TOKEN_NAME);
        assert_eq!(m.value.as_str(), "sbrt_refresh_MOCK");
        assert!(m.sensitive);
        // rotation dispatches to the self-rotating management provider.
        assert_eq!(outcome.rotation_config.provider, "supabase-management");
        assert_eq!(
            outcome.rotation_config.api_key_env.as_deref(),
            Some(SUPABASE_REFRESH_TOKEN_NAME)
        );
        assert!(outcome.rotation_config.account_id.is_none());
        assert_eq!(outcome.metadata.account.as_deref(), Some("ashlrai"));

        // Authorize URL: S256 PKCE, a state, and the org pre-select.
        let urls = browser.urls.lock().unwrap();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("code_challenge_method=S256"));
        assert!(urls[0].contains("state="));
        assert!(urls[0].contains("organization_slug=ashlrai"));

        // Exchange: Basic auth header, PKCE verifier, NO client_secret in body.
        let requests = seen.lock().unwrap();
        let req_text = &requests[0];
        assert!(
            req_text.contains("authorization: Basic ")
                || req_text.contains("Authorization: Basic ")
        );
        assert!(req_text.contains("grant_type=authorization_code"));
        assert!(req_text.contains("code_verifier="));
        assert!(!req_text.contains("client_secret="));
        assert!(!req_text.contains("sb_client_secret_MOCK"));

        // Redacting Debug never renders the refresh token.
        assert!(!format!("{outcome:?}").contains("sbrt_refresh_MOCK"));
    }

    #[test]
    fn oauth_flow_requires_client_secret() {
        let _g = env_guard();
        let http = crate::issuance::build_http_client().unwrap();
        let ep = endpoints("https://api.supabase.com/v1/oauth/token".to_string());
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("code", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let mut req = request(None);
        req.client_secret = None;
        assert!(matches!(
            SupabaseOAuthFlow.issue(&req, &deps),
            Err(IssuanceError::NotSupported { .. })
        ));
    }

    #[test]
    fn oauth_flow_state_mismatch_is_csrf_denied() {
        let _g = env_guard();
        let http = crate::issuance::build_http_client().unwrap();
        let ep = endpoints("http://127.0.0.1:0/v1/oauth/token".to_string());
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("code", MockStateMode::Tamper);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        assert_eq!(
            SupabaseOAuthFlow.issue(&request(None), &deps).unwrap_err(),
            IssuanceError::ConsentDenied
        );
    }

    // ── Management provider ───────────────────────────────────────────────────

    fn base_config(account_id: Option<&str>) -> RotationProviderConfig {
        RotationProviderConfig {
            provider: SUPABASE_MANAGEMENT_PROVIDER.to_string(),
            api_key_env: Some("SUPABASE_REFRESH_TOKEN".to_string()),
            account_id: account_id.map(|s| s.to_string()),
            region: None,
            timeout_secs: 30,
            enabled: true,
        }
    }

    #[test]
    fn mode_a_refreshes_and_returns_new_refresh_token_atomically() {
        let _g = env_guard();
        let (base, seen) = spawn_stub(
            200,
            r#"{"access_token":"sbat_new_MOCK","refresh_token":"sbrt_rotated_MOCK","expires_in":86400}"#,
        );
        std::env::set_var(ENV_SUPABASE_API_BASE, &base);
        std::env::set_var(ENV_SUPABASE_CLIENT_ID, "sb_client_id");
        std::env::set_var(ENV_SUPABASE_CLIENT_SECRET, "sb_client_secret_MOCK");
        std::env::set_var("SUPABASE_REFRESH_TOKEN", "sbrt_old_real_value");

        let config = base_config(None);
        let challenge = SupabaseManagementProvider
            .initiate_rotation("SUPABASE_REFRESH_TOKEN", &config)
            .unwrap();
        let new_value = SupabaseManagementProvider
            .finalize_rotation(&challenge, &config)
            .unwrap();

        assert_eq!(new_value.as_str(), "sbrt_rotated_MOCK");
        // Refresh grant used Basic auth + grant_type=refresh_token.
        let requests = seen.lock().unwrap();
        assert!(requests[0].contains("grant_type=refresh_token"));
        assert!(
            requests[0].contains("Basic ")
                || requests[0].to_lowercase().contains("authorization: basic")
        );
        // Never render the token in the challenge Debug.
        assert!(!format!("{challenge:?}").contains("sbrt_rotated_MOCK"));

        std::env::remove_var(ENV_SUPABASE_API_BASE);
        std::env::remove_var(ENV_SUPABASE_CLIENT_ID);
        std::env::remove_var(ENV_SUPABASE_CLIENT_SECRET);
        std::env::remove_var("SUPABASE_REFRESH_TOKEN");
    }

    #[test]
    fn mode_a_401_reports_user_revoked() {
        let _g = env_guard();
        let (base, _seen) = spawn_stub(401, r#"{"message":"unauthorized"}"#);
        std::env::set_var(ENV_SUPABASE_API_BASE, &base);
        std::env::set_var(ENV_SUPABASE_CLIENT_ID, "sb_client_id");
        std::env::set_var(ENV_SUPABASE_CLIENT_SECRET, "sb_client_secret_MOCK");
        std::env::set_var("SUPABASE_REFRESH_TOKEN", "sbrt_old_real_value");

        let err = SupabaseManagementProvider
            .initiate_rotation("SUPABASE_REFRESH_TOKEN", &base_config(None))
            .unwrap_err();
        assert!(matches!(err, RotationProviderError::AuthFailed { .. }));
        assert!(format!("{err}").to_lowercase().contains("disconnect"));

        std::env::remove_var(ENV_SUPABASE_API_BASE);
        std::env::remove_var(ENV_SUPABASE_CLIENT_ID);
        std::env::remove_var(ENV_SUPABASE_CLIENT_SECRET);
        std::env::remove_var("SUPABASE_REFRESH_TOKEN");
    }

    #[test]
    fn mode_b_mints_project_api_key() {
        let _g = env_guard();
        let (base, seen) = spawn_stub(
            201,
            r#"{"id":"key_123","api_key":"sb_secret_minted_MOCK","type":"secret"}"#,
        );
        std::env::set_var(ENV_SUPABASE_API_BASE, &base);
        std::env::set_var("SUPABASE_PROJECT_KEY", "sbat_management_access_token");

        let mut config = base_config(Some("abcdefghijklmnop"));
        config.api_key_env = Some("SUPABASE_PROJECT_KEY".to_string());
        let challenge = SupabaseManagementProvider
            .initiate_rotation("SUPABASE_PROJECT_KEY", &config)
            .unwrap();
        let new_value = SupabaseManagementProvider
            .finalize_rotation(&challenge, &config)
            .unwrap();

        assert_eq!(new_value.as_str(), "sb_secret_minted_MOCK");
        let requests = seen.lock().unwrap();
        assert!(requests[0].contains("/v1/projects/abcdefghijklmnop/api-keys"));
        assert!(requests[0].to_lowercase().contains("authorization: bearer"));
        assert!(!format!("{challenge:?}").contains("sb_secret_minted_MOCK"));

        std::env::remove_var(ENV_SUPABASE_API_BASE);
        std::env::remove_var("SUPABASE_PROJECT_KEY");
    }

    #[test]
    fn mock_bootstrap_takes_guarded_fast_path() {
        let _g = env_guard();
        std::env::set_var("SUPABASE_REFRESH_TOKEN", "sbmock_bootstrap");
        let config = base_config(None);
        let challenge = SupabaseManagementProvider
            .initiate_rotation("SUPABASE_REFRESH_TOKEN", &config)
            .unwrap();
        let value = SupabaseManagementProvider
            .finalize_rotation(&challenge, &config)
            .unwrap();
        assert_eq!(value.as_str(), "sb_secret_rotated_mock_value");
        std::env::remove_var("SUPABASE_REFRESH_TOKEN");
    }

    #[test]
    fn provider_identity_is_distinct_from_manual_supabase() {
        assert_eq!(SupabaseManagementProvider.name(), "supabase-management");
        assert_eq!(
            SupabaseManagementProvider.rotation_source().label(),
            "supabase-management"
        );
    }

    #[test]
    fn api_base_override_ignored_without_mock_and_for_bad_scheme() {
        // Not https/localhost → rejected regardless.
        assert!(!is_https_or_localhost("http://evil.example.com"));
        assert!(!is_https_or_localhost("http://127.0.0.1.attacker.com/"));
        assert!(is_https_or_localhost("https://api.supabase.com"));
        assert!(is_https_or_localhost("http://127.0.0.1:52100"));
    }

    #[test]
    fn basic_auth_header_encodes_credentials() {
        use base64::Engine as _;
        let header = basic_auth_header("id", &Zeroizing::new("secret".to_string()));
        let expected = base64::engine::general_purpose::STANDARD.encode(b"id:secret");
        assert_eq!(header, format!("Basic {expected}"));
    }
}
