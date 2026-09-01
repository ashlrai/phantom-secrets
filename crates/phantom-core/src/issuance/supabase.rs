//! Supabase OAuth and Management-API protocol foundations.
//!
//! Shipped 0.7.4 returns `NotSupported` before OAuth request, browser,
//! loopback, credential, or network access. Consent protocol execution is
//! confined to crate-local overridden-endpoint tests.
//!
//! Two halves with an explicit fresh-consent boundary:
//!
//! 1. [`SupabaseOAuthFlow`] — one human "Authorize" flow. Authorization
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
//! 2. [`SupabaseManagementProvider`] — the Management-API provider, a
//!    [`RotationProvider`] with a distinct identity (`"supabase-management"`,
//!    NOT the manual-only `"supabase"` PAT provider). Two trait-coherent modes,
//!    dispatched by whether `account_id` names a project ref:
//!    - **management-token self-rotation** (`account_id` = `None`) is hard
//!      denied before credential access or network I/O. Supabase invalidates
//!      the current refresh token during exchange, before Phantom can durably
//!      verify its successor. The vaulted token remains enrollment material;
//!      expiration requires fresh operator consent until recovery escrow exists.
//!    - **project-API-key minting** (`account_id` = a project ref) is also hard
//!      denied in shipped builds. The current challenge contract cannot durably
//!      preserve the successor key id for compensating DELETE if local
//!      persistence fails. `cfg(test)` mocks cover local transaction behavior.
//!
//! # Security
//!
//! - Application-owned parsed token buffers use [`Zeroizing`] and no token is
//!   intentionally logged, printed, or surfaced in an error/JSON. Transport
//!   headers, encoded Basic-auth strings, and HTTP library request buffers are
//!   not proven to be zeroized by their dependencies.
//! - Vendor error bodies pass through
//!   [`crate::rotation_provider::summarize_error_body`] (type/code/status only).
//! - Both HTTP clients disable redirects (`redirect(Policy::none())`): the
//!   consent exchange uses the issuance client, the refresh grant uses the
//!   shared rotation client — neither will replay the secret-bearing body to a
//!   3xx target. A `401` on refresh is surfaced as "the user revoked the app"
//!   — never a silent demotion.
//! - The Management-API base is fixed in shipped builds. Only `cfg(test)` unit
//!   tests compile the loopback override used by the hermetic HTTP stubs.

use serde_json::Value;
use zeroize::Zeroizing;

use super::pkce::{
    build_authorize_url, code_challenge_s256, generate_code_verifier, map_oauth_error, now_unix,
};
use super::{
    guard_test_only_issuance, random_state, ConsentEngine, GrantType, IssuanceDeps, IssuanceError,
    IssuanceMetadata, IssuanceOutcome, IssuanceRequest, IssuedMaterial, MaterialKind,
};
use crate::rotation_provider::{
    guard_mock_rotation, mock_rotation_allowed, redact_challenge_id, resolve_api_key,
    summarize_error_body, CleanupOutcome, CleanupSemantics, RotationProvider,
    RotationProviderConfig, RotationProviderError, RotationSource,
};

// ── Constants ────────────────────────────────────────────────────────────────

/// Vault name the refresh-token enrollment material is stored under. Contains
/// `SUPABASE` + `REFRESH_TOKEN` so operators recognize its lifecycle.
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
        guard_test_only_issuance(deps)?;

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
                reason: "no authorize/token endpoint known for supabase".to_string(),
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
/// refresh token is vaulted enrollment material; the access token / expiries
/// are metadata only. The generated compatibility rotation block is disabled
/// because refresh exchange is not recoverable transactionally.
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
        // No account_id identifies the destructive refresh mode. Keep the
        // compatibility block disabled; additive project-key minting requires
        // an independently configured account_id and management access token.
        account_id: None,
        enabled: false,
        ..Default::default()
    };
    let metadata = IssuanceMetadata {
        display_name: "supabase".to_string(),
        account: org.map(|s| s.to_string()),
        scopes: scopes.to_vec(),
        expires_at,
        notes: vec![
            "Automatic Supabase refresh-token rotation is disabled: exchange invalidates the \
             current token before Phantom can durably verify its successor. Keep this vaulted \
             enrollment material; when it expires, obtain fresh operator consent with \
             `phantom grant add supabase` until verified recovery escrow exists."
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

/// Supabase Management-API compatibility provider. Shipped builds hard-deny
/// both issuance modes; see the module safety boundaries. Registered in
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
        if config.account_id.is_none() {
            return Err(RotationProviderError::NotSupported {
                reason: "Supabase management refresh-token rotation is disabled before credential access or provider issuance: the refresh exchange invalidates the current token before Phantom can durably verify its successor. A durable verified recovery escrow channel is required. Keep the vaulted enrollment material and obtain fresh operator consent when it expires. Do not retry automatically."
                    .to_string(),
            });
        }
        if !mock_rotation_allowed() {
            return Err(RotationProviderError::NotSupported {
                reason: "Live Supabase project-key issuance is disabled before credential access or network I/O: Phantom cannot durably retain a value-free successor resource id and delete the issued key if local vault persistence fails. Create the key in Supabase and store it interactively. Do not retry automatically."
                    .to_string(),
            });
        }
        let bootstrap = resolve_api_key(config)?;

        // Hermetic mock fast-path (guarded — fails closed off cfg(test)).
        if bootstrap.starts_with(MOCK_BOOTSTRAP_PREFIX) {
            guard_mock_rotation(secret_name)?;
            return Ok(format!("mock_challenge_supabase_{secret_name}"));
        }

        Err(RotationProviderError::NotSupported {
            reason: "Live Supabase project-key issuance is disabled before network access: the current provider challenge contract does not preserve a value-free successor resource id for compensating cleanup if local vault persistence fails. Create the key in Supabase and store it interactively. Do not retry automatically."
                .to_string(),
        })
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
        Err(RotationProviderError::NotSupported {
            reason: "Only cfg(test) Supabase mock challenges can be finalized".to_string(),
        })
    }

    /// Cleanup is disabled with live issuance. Exact mock values remain a
    /// hermetic transaction-test seam and never reach the network.
    fn cleanup_semantics(&self, config: &RotationProviderConfig) -> CleanupSemantics {
        if config.account_id.is_some() {
            CleanupSemantics::RevokePriorCredential
        } else {
            CleanupSemantics::NotApplicable
        }
    }

    fn post_store_cleanup(
        &self,
        secret_name: &str,
        config: &RotationProviderConfig,
        old_value: Option<&Zeroizing<String>>,
    ) -> Result<CleanupOutcome, RotationProviderError> {
        let Some(project_ref) = config.account_id.as_deref() else {
            return Ok(CleanupOutcome::NotApplicable);
        };
        let Some(old) = old_value else {
            crate::audit::log("vault.rotation.old_token_revoke_skipped", Some(secret_name));
            return Ok(CleanupOutcome::SkippedNoPriorCredential);
        };
        // Mock / rotated-mock values never reach the network.
        if old.starts_with(MOCK_BOOTSTRAP_PREFIX) || old.starts_with("sb_secret_rotated_mock") {
            guard_mock_rotation(secret_name)?;
            return Ok(CleanupOutcome::SkippedMockCredential);
        }
        let _ = project_ref;
        Err(RotationProviderError::NotSupported {
            reason: "Live Supabase prior-key cleanup is disabled before credential or network access together with live issuance. Revoke provider credentials directly in the Supabase dashboard and verify the result; do not retry automatically."
                .to_string(),
        })
    }

    fn rotation_source(&self) -> RotationSource {
        RotationSource::Custom {
            provider_name: SUPABASE_MANAGEMENT_PROVIDER.to_string(),
        }
    }
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
    fn env_guard() -> crate::ProcessEnvGuard {
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
        // The compatibility block is present but disabled because the refresh
        // exchange is destructive before local persistence.
        assert_eq!(outcome.rotation_config.provider, "supabase-management");
        assert_eq!(
            outcome.rotation_config.api_key_env.as_deref(),
            Some(SUPABASE_REFRESH_TOKEN_NAME)
        );
        assert!(outcome.rotation_config.account_id.is_none());
        assert!(!outcome.rotation_config.enabled);
        assert!(outcome.metadata.notes.iter().any(|note| {
            note.contains("Automatic Supabase refresh-token rotation is disabled")
                && note.contains("fresh operator consent")
        }));
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
    fn mode_a_is_denied_before_bootstrap_access() {
        let _g = env_guard();
        std::env::remove_var("SUPABASE_REFRESH_TOKEN");
        let error = SupabaseManagementProvider
            .initiate_rotation("SUPABASE_REFRESH_TOKEN", &base_config(None))
            .expect_err("Mode A must fail before bootstrap lookup");
        assert!(matches!(error, RotationProviderError::NotSupported { .. }));
        assert!(error.to_string().contains("recovery escrow"));
        assert!(error.to_string().contains("Do not retry automatically"));
    }

    #[test]
    fn mode_a_mock_is_also_denied() {
        let _g = env_guard();
        std::env::set_var("SUPABASE_REFRESH_TOKEN", "sbmock_bootstrap");

        let err = SupabaseManagementProvider
            .initiate_rotation("SUPABASE_REFRESH_TOKEN", &base_config(None))
            .unwrap_err();
        assert!(matches!(err, RotationProviderError::NotSupported { .. }));

        std::env::remove_var("SUPABASE_REFRESH_TOKEN");
    }

    #[test]
    fn mode_b_non_mock_is_denied_before_network() {
        let _g = env_guard();
        std::env::set_var("SUPABASE_PROJECT_KEY", "sbat_management_access_token");

        let mut config = base_config(Some("abcdefghijklmnop"));
        config.api_key_env = Some("SUPABASE_PROJECT_KEY".to_string());
        let error = SupabaseManagementProvider
            .initiate_rotation("SUPABASE_PROJECT_KEY", &config)
            .expect_err("non-mock Mode B issuance must be denied");
        assert!(matches!(error, RotationProviderError::NotSupported { .. }));
        assert!(error
            .to_string()
            .contains("current provider challenge contract"));

        std::env::remove_var("SUPABASE_PROJECT_KEY");
    }

    #[test]
    fn mode_b_mock_bootstrap_takes_guarded_fast_path() {
        let _g = env_guard();
        std::env::set_var("SUPABASE_REFRESH_TOKEN", "sbmock_bootstrap");
        let config = base_config(Some("abcdefghijklmnop"));
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
    fn mode_b_nonmock_cleanup_is_denied_before_credential_or_network() {
        let _g = env_guard();
        let mut config = base_config(Some("abcdefghijklmnop"));
        config.api_key_env = Some("UNSET_SUPABASE_PROJECT_ADMIN".to_string());
        let old = Zeroizing::new("sb_secret_prior_value".to_string());

        let error = SupabaseManagementProvider
            .post_store_cleanup("SUPABASE_PROJECT_KEY", &config, Some(&old))
            .expect_err("live cleanup must be disabled before credential lookup");

        assert!(matches!(error, RotationProviderError::NotSupported { .. }));
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
    fn basic_auth_header_encodes_credentials() {
        use base64::Engine as _;
        let header = basic_auth_header("id", &Zeroizing::new("secret".to_string()));
        let expected = base64::engine::general_purpose::STANDARD.encode(b"id:secret");
        assert_eq!(header, format!("Basic {expected}"));
    }
}
