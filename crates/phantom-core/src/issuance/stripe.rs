//! Stripe App OAuth — the `oauth-refresh` grant for Stripe.
//!
//! [`StripeAppOAuthFlow`] runs the ONE human "accept permissions" click on a
//! Phantom Stripe App configured with `stripe_api_access_type=oauth`, then
//! exchanges the resulting 5-minute authorization code for a **1-hour access
//! token** off a **1-year rolling refresh token** (Stripe's *oauth-refresh*
//! grant). It mirrors [`super::vercel::VercelIntegrationFlow`]'s loopback code
//! capture: bind an ephemeral `127.0.0.1` listener, open the Stripe authorize
//! page, capture the redirect `?code=…&state=…`, verify the CSRF `state`, then
//! exchange the code at `POST /v1/oauth/token`.
//!
//! The refresh token is the durable root; it is returned only via
//! [`IssuanceOutcome`] for the CLI to vault, and is **never** logged, printed,
//! emitted in `--json`, or carried in an MCP response. The 1-hour access token
//! is a drop-in API-key substitute minted on demand — nearly worthless if
//! leaked — so it is never the stored root.
//!
//! # Confidential client — the developer's own secret key
//!
//! Unlike GitHub/Vercel (which pass a per-app `client_secret` in the body),
//! Stripe authenticates the token exchange with **Phantom's own developer
//! secret key** via HTTP Basic auth (`-u "sk_…:"`). Phantom (the vendor) holds
//! that key in an env var / vault — never each user — and it is handed to the
//! engine as [`IssuanceRequest::client_secret`] (`Zeroizing`, never read from
//! disk here). There is no PKCE: Stripe's OAuth surfaces are confidential-client
//! only (verified 2026-08).
//!
//! # Refresh rolling & the 1-year window
//!
//! The refresh token expires 1 year after issue but is **rolled on every
//! exchange** — any refresh cadence under a year makes it immortal. Issuance
//! stamps a 1-year `expires_at` in metadata and writes the `rotation_provider`
//! block so `phantom rotate --name STRIPE_REFRESH_TOKEN` performs the
//! `grant_type=refresh_token` roll (see
//! [`crate::rotation_provider::StripeRotationProvider`], the *additive*
//! oauth-refresh path).
//!
//! # STRIPE_KOALA_TEST and raw restricted keys
//!
//! Stripe exposes **no public API** to create restricted (`rk_`) or secret
//! (`sk_`) keys — that is dashboard-only, behind an interactive 2FA dialog.
//! [`StripeRestrictedKeyFlow`] is therefore a fail-closed `NotSupported`
//! engine: it performs no I/O and returns the exact sandbox dashboard link,
//! steering the operator to the recommended OAuth flow. For a test-mode key
//! like `STRIPE_KOALA_TEST`, a one-time sandbox restricted key (always
//! revealable, never expires) stored via `phantom add` is the pragmatic floor.

use zeroize::Zeroizing;

use super::{
    guard_mock_issuance, random_state, ConsentEngine, GrantType, IssuanceDeps, IssuanceError,
    IssuanceMetadata, IssuanceOutcome, IssuanceRequest, IssuedMaterial, MaterialKind,
};
use crate::rotation_provider::{summarize_error_body, RotationProviderConfig};

/// Fixed vault name the durable 1-year refresh token is stored under. Contains
/// `STRIPE` and `TOKEN` so [`crate::rotation_provider::StripeRotationProvider`]
/// matches it and `phantom rotate --name STRIPE_REFRESH_TOKEN` dispatches; the
/// `_REFRESH_TOKEN` suffix is what selects the provider's oauth-refresh path.
pub const STRIPE_REFRESH_TOKEN_NAME: &str = "STRIPE_REFRESH_TOKEN";

/// Vault name for the Stripe publishable key (`pk_…`). Publishable keys are
/// non-secret by design; vaulted for completeness so a worker has the pair.
pub const STRIPE_PUBLISHABLE_KEY_NAME: &str = "STRIPE_PUBLISHABLE_KEY";

/// Consent window for the "accept permissions" click (matches the other engines).
const CONSENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Stripe refresh tokens expire 1 year after issue (rolled on every use). Used
/// only to stamp a non-secret `expires_at` so expiry tooling flags a stale
/// chain — never the token bytes.
const STRIPE_REFRESH_TTL_SECS: u64 = 365 * 24 * 60 * 60;

// ── OAuth-refresh engine ──────────────────────────────────────────────────────

/// The Stripe App OAuth consent engine (grant type `OauthRefresh`).
pub struct StripeAppOAuthFlow;

impl ConsentEngine for StripeAppOAuthFlow {
    fn name(&self) -> &str {
        "stripe-app-oauth"
    }

    fn grant_type(&self) -> GrantType {
        GrantType::OauthRefresh
    }

    fn issue(
        &self,
        req: &IssuanceRequest,
        deps: &IssuanceDeps,
    ) -> Result<IssuanceOutcome, IssuanceError> {
        // Fail closed: an overridden (non-production) endpoint may only be hit
        // when mock issuance is explicitly enabled. This stops a prompt-injected
        // agent from redirecting the exchange — and the refresh token it yields —
        // to an attacker-controlled host.
        if deps.endpoints.overridden {
            guard_mock_issuance()?;
        }

        // The Stripe App is a confidential client: `client_id` is the app's
        // OAuth client id (`ca_…`); the exchange is authenticated with the app
        // developer's own Stripe secret key (HTTP Basic), resolved from an env
        // var by the CLI and handed in as Zeroizing — never read from disk here.
        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| IssuanceError::NotSupported {
                reason: "stripe requires --client-id (the Stripe App's OAuth client id, ca_…, \
                         from `stripe apps` / the app settings)"
                    .to_string(),
            })?;
        let developer_secret =
            req.client_secret
                .as_ref()
                .ok_or_else(|| IssuanceError::NotSupported {
                    reason: "stripe requires the app developer's Stripe secret key for the token \
                             exchange; pass --client-secret-env NAME (defaults to \
                             STRIPE_APP_SECRET_KEY). It is never read from disk."
                        .to_string(),
                })?;
        if deps.endpoints.authorize.is_empty() || deps.endpoints.token.is_empty() {
            return Err(IssuanceError::NotSupported {
                reason: "no authorize/token endpoint is known for stripe".to_string(),
            });
        }

        // 1. Loopback listener on 127.0.0.1:0 (RFC 8252 §7.3).
        let binding = deps.loopback.bind()?;
        let state = random_state();

        // 2. Open the Stripe authorize page. Stripe redirects the 5-minute code
        //    back to the loopback `/callback`. The URL carries a `state` (CSRF)
        //    and the loopback `redirect_uri`, no secret.
        let authorize_url = build_query_url(
            &deps.endpoints.authorize,
            &[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", binding.redirect_uri.as_str()),
                ("state", state.as_str()),
                ("scope", req.scopes.join(" ").as_str()),
            ],
        );
        deps.browser.open(&authorize_url);
        eprintln!("Open this URL to authorize the Phantom Stripe App: {authorize_url}");

        // 3. Capture the redirect code (Zeroizing), verify CSRF state.
        let captured = deps.loopback.wait(&state, None, CONSENT_TIMEOUT)?;
        if captured.state != state {
            return Err(IssuanceError::ConsentDenied);
        }
        let code = captured.code; // Zeroizing<String>

        // 4. Exchange the code for the refresh + access token. Basic auth with
        //    the developer secret key (username = secret, empty password), matching
        //    Stripe's `-u "sk_…:"`. No client_secret in the body, no PKCE.
        let body = stripe_token_exchange(
            deps,
            developer_secret,
            &[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
            ],
        )?;

        build_stripe_outcome(req, &body)
    }
}

/// POST the token endpoint with HTTP Basic auth (developer secret key) and a
/// form body, returning the parsed success JSON. Non-2xx and in-body `error`
/// fields are summarized (never the raw body) before surfacing.
fn stripe_token_exchange(
    deps: &IssuanceDeps,
    developer_secret: &Zeroizing<String>,
    form: &[(&str, &str)],
) -> Result<serde_json::Value, IssuanceError> {
    let response = deps
        .http
        .post(&deps.endpoints.token)
        .basic_auth(developer_secret.as_str(), Some(""))
        .header("Accept", "application/json")
        .header("User-Agent", "phantom-secrets/0.1")
        .form(form)
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

    let body: serde_json::Value =
        response
            .json()
            .map_err(|e| IssuanceError::UnexpectedResponse {
                reason: e.to_string(),
            })?;

    // Stripe reports OAuth failures as a top-level `error` string even on 200.
    if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
        return Err(IssuanceError::Exchange {
            status,
            reason: format!("error={}", err.chars().take(64).collect::<String>()),
        });
    }
    Ok(body)
}

/// Turn a successful `/v1/oauth/token` body into a vaultable outcome.
///
/// The `refresh_token` is the durable, 1-year rolling root (kept in `Zeroizing`,
/// never rendered). `stripe_user_id` (`acct_…`, non-secret) prefers the exchange
/// body, else the `--account` hint; it plumbs through to `account_id`. The
/// `access_token` (1-hour) is deliberately NOT vaulted — it is minted on demand.
fn build_stripe_outcome(
    req: &IssuanceRequest,
    body: &serde_json::Value,
) -> Result<IssuanceOutcome, IssuanceError> {
    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::UnexpectedResponse {
            reason: "token response has no refresh_token — the Stripe App must use \
                     stripe_api_access_type=oauth to issue a rolling refresh token"
                .to_string(),
        })?;
    let refresh_token = Zeroizing::new(refresh_token.to_string());

    // stripe_user_id (acct_…) is NOT a secret. The exchange body is authoritative;
    // an explicit --account is only an advisory fallback.
    let account = body
        .get("stripe_user_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| req.account.clone());

    let mut materials = vec![IssuedMaterial {
        phm_name: STRIPE_REFRESH_TOKEN_NAME.to_string(),
        value: refresh_token,
        kind: MaterialKind::RefreshToken,
        sensitive: true,
    }];

    // The publishable key (pk_…) is non-secret; vault it non-sensitive so a
    // worker has the client/server pair. Skipped when absent.
    if let Some(pk) = body
        .get("stripe_publishable_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        materials.push(IssuedMaterial {
            phm_name: STRIPE_PUBLISHABLE_KEY_NAME.to_string(),
            value: Zeroizing::new(pk.to_string()),
            kind: MaterialKind::ClientId,
            sensitive: false,
        });
    }

    // Write the rotation_provider block so `phantom rotate --name
    // STRIPE_REFRESH_TOKEN` rolls the refresh token (grant_type=refresh_token),
    // keeping the 1-year chain alive. account_id scopes acct_-aware calls.
    let rotation_config = RotationProviderConfig {
        provider: "stripe".to_string(),
        api_key_env: Some(STRIPE_REFRESH_TOKEN_NAME.to_string()),
        account_id: account.clone(),
        region: None,
        timeout_secs: 30,
        enabled: true,
    };

    let scope = body
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| req.scopes.clone());

    let mut notes = vec![
        "1-hour access tokens are minted on demand from the vaulted refresh token — \
         never stored, never shown."
            .to_string(),
        "`phantom rotate --name STRIPE_REFRESH_TOKEN` rolls the 1-year refresh token; \
         any cadence under a year keeps the chain immortal."
            .to_string(),
    ];
    if let Some(acct) = account.as_deref() {
        notes.push(format!("Authorized Stripe account: {acct}."));
    }

    let metadata = IssuanceMetadata {
        display_name: "Phantom Stripe App".to_string(),
        account,
        scopes: scope,
        expires_at: Some(now_unix().saturating_add(STRIPE_REFRESH_TTL_SECS)),
        notes,
        ..Default::default()
    };

    Ok(IssuanceOutcome {
        provider: "stripe".to_string(),
        grant_type: GrantType::OauthRefresh,
        materials,
        rotation_config,
        metadata,
    })
}

// ── Restricted-key engine (fail-closed, dashboard-only) ───────────────────────

/// Fail-closed engine for raw restricted (`rk_`) / secret (`sk_`) key creation.
///
/// Stripe has no public API to create, reveal, or rotate `rk_`/`sk_` keys —
/// that is dashboard-only, behind an interactive 2FA dialog. This engine
/// performs **no** network I/O and returns [`IssuanceError::NotSupported`] with
/// the exact sandbox dashboard link, recommending the OAuth flow. It is the
/// honest "manual grant" path for a key like `STRIPE_KOALA_TEST`.
pub struct StripeRestrictedKeyFlow;

/// Operator-facing guidance surfaced by [`StripeRestrictedKeyFlow`].
const STRIPE_RAK_NOT_SUPPORTED_REASON: &str =
    "Stripe has no public API to create restricted (rk_) or secret (sk_) API keys — \
     creation is dashboard-only, behind an interactive 2FA dialog. For a test-mode key \
     (e.g. STRIPE_KOALA_TEST): create a sandbox restricted key at \
     https://dashboard.stripe.com/test/apikeys/create (sandbox keys are always revealable \
     and never expire), then store it with `phantom add STRIPE_KOALA_TEST`. \
     RECOMMENDED for a self-refreshing credential: use the OAuth app flow instead — \
     `phantom grant add stripe --client-id <ca_…>` — which mints 1-hour access tokens off \
     a 1-year rolling refresh token, fully unattended.";

impl ConsentEngine for StripeRestrictedKeyFlow {
    fn name(&self) -> &str {
        "stripe-restricted-key"
    }

    fn grant_type(&self) -> GrantType {
        GrantType::Manual
    }

    fn issue(
        &self,
        _req: &IssuanceRequest,
        _deps: &IssuanceDeps,
    ) -> Result<IssuanceOutcome, IssuanceError> {
        // No I/O, no partial vault — refuse honestly with the dashboard link.
        Err(IssuanceError::NotSupported {
            reason: STRIPE_RAK_NOT_SUPPORTED_REASON.to_string(),
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Current unix time in seconds (0 on a pre-epoch clock).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build `base?k=v&…`, percent-encoding each value and skipping empty ones.
fn build_query_url(base: &str, params: &[(&str, &str)]) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let query: Vec<String> = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v)))
        .collect();
    if query.is_empty() {
        return base.to_string();
    }
    format!("{base}{sep}{}", query.join("&"))
}

/// Percent-encode per RFC 3986 (unreserved set kept verbatim).
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuance::browser::BrowserOpener;
    use crate::issuance::endpoints::Endpoints;
    use crate::issuance::loopback::{MockLoopbackListener, MockStateMode};
    use std::sync::Mutex;

    /// Serialize env/audit-touching issuance tests: `guard_mock_issuance` emits a
    /// `grant.issuance.mock` event to the ambient audit log, which an audit test
    /// that repointed `HOME`/`PHANTOM_AUDIT` would otherwise miscount. Same idiom
    /// the pkce/device/vercel/audit tests use; poison-tolerant so one panicking
    /// test never cascades into the rest of the suite.
    fn issue_audit_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Capturing browser: records the authorize URL for assertions.
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
    /// request text (headers + body) so tests can assert what the engine sent.
    fn spawn_stub(status: u16, body: &'static str) -> (String, std::sync::Arc<Mutex<Vec<String>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
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
            authorize: "https://marketplace.stripe.com/oauth/v2/authorize".to_string(),
            token,
            device_code: String::new(),
            overridden: true, // exercises the mock gate (allowed under cfg(test))
        }
    }

    fn request(account: Option<&str>) -> IssuanceRequest {
        IssuanceRequest {
            provider: "stripe".to_string(),
            client_id: Some("ca_phantom_app".to_string()),
            client_secret: Some(Zeroizing::new("sk_test_developer_MOCK".to_string())),
            scopes: vec![],
            flow: None,
            app_manifest: None,
            team_id: None,
            account: account.map(str::to_string),
            org: None,
        }
    }

    fn run(req: &IssuanceRequest, token_url: String) -> (IssuanceOutcome, Vec<String>) {
        let http = reqwest::blocking::Client::new();
        let ep = endpoints(token_url);
        let browser = CapturingBrowser {
            urls: Mutex::new(Vec::new()),
        };
        let loopback = MockLoopbackListener::new("ac_stripe_code_123", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let outcome = StripeAppOAuthFlow.issue(req, &deps).unwrap();
        let urls = browser.urls.lock().unwrap().clone();
        (outcome, urls)
    }

    #[test]
    fn oauth_exchange_vaults_refresh_token_and_never_prints_it() {
        let _g = issue_audit_guard();
        let (base, seen) = spawn_stub(
            200,
            r#"{"access_token":"sk_test_access_MOCK","refresh_token":"rt_test_refresh_MOCK","stripe_user_id":"acct_MOCK123","stripe_publishable_key":"pk_test_MOCK","scope":"read_write","livemode":false,"token_type":"bearer"}"#,
        );
        let req = request(None);
        let (outcome, urls) = run(&req, format!("{base}/v1/oauth/token"));

        // Durable root: the 1-year rolling refresh token, under the fixed name.
        let refresh = outcome
            .materials
            .iter()
            .find(|m| m.phm_name == STRIPE_REFRESH_TOKEN_NAME)
            .expect("refresh material");
        assert_eq!(refresh.value.as_str(), "rt_test_refresh_MOCK");
        assert!(refresh.sensitive);
        assert_eq!(refresh.kind, MaterialKind::RefreshToken);

        // Publishable key is vaulted non-sensitive.
        let pk = outcome
            .materials
            .iter()
            .find(|m| m.phm_name == STRIPE_PUBLISHABLE_KEY_NAME)
            .expect("publishable material");
        assert!(!pk.sensitive);
        assert_eq!(pk.value.as_str(), "pk_test_MOCK");

        // The access token is NEVER vaulted (ephemeral, minted on demand).
        assert!(
            !outcome
                .materials
                .iter()
                .any(|m| m.value.as_str() == "sk_test_access_MOCK"),
            "the 1-hour access token must not be vaulted"
        );

        assert_eq!(outcome.provider, "stripe");
        assert_eq!(outcome.grant_type, GrantType::OauthRefresh);
        assert_eq!(outcome.rotation_config.provider, "stripe");
        assert_eq!(
            outcome.rotation_config.api_key_env.as_deref(),
            Some(STRIPE_REFRESH_TOKEN_NAME)
        );
        assert_eq!(
            outcome.rotation_config.account_id.as_deref(),
            Some("acct_MOCK123")
        );
        assert_eq!(outcome.metadata.account.as_deref(), Some("acct_MOCK123"));
        // The 1-year refresh expiry is stamped for expiry tooling.
        assert!(outcome.metadata.expires_at.unwrap() > now_unix());

        // The authorize URL the browser saw is a code flow with a CSRF state and
        // the app client id — never the developer secret key.
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("response_type=code"));
        assert!(urls[0].contains("client_id=ca_phantom_app"));
        assert!(urls[0].contains("state="));
        assert!(!urls[0].contains("sk_test_developer_MOCK"));

        // The exchange POSTed the code with grant_type, and authenticated the
        // developer secret via HTTP Basic (Authorization header), NOT the body.
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("grant_type=authorization_code"));
        assert!(requests[0].contains("code=ac_stripe_code_123"));
        assert!(
            requests[0].to_lowercase().contains("authorization: basic "),
            "developer secret must travel as HTTP Basic auth"
        );
        assert!(
            !requests[0].contains("sk_test_developer_MOCK"),
            "developer secret must never appear in the clear in the request"
        );

        // Redacting Debug never renders the refresh token.
        let dbg = format!("{outcome:?}");
        assert!(dbg.contains("[redacted]"));
        assert!(!dbg.contains("rt_test_refresh_MOCK"));
    }

    #[test]
    fn account_hint_is_fallback_when_body_lacks_stripe_user_id() {
        let _g = issue_audit_guard();
        let (base, _seen) = spawn_stub(
            200,
            r#"{"access_token":"sk_test_access_MOCK","refresh_token":"rt_test_refresh_MOCK","scope":"read_write"}"#,
        );
        let req = request(Some("acct_from_flag"));
        let (outcome, _urls) = run(&req, format!("{base}/v1/oauth/token"));
        assert_eq!(
            outcome.rotation_config.account_id.as_deref(),
            Some("acct_from_flag")
        );
        assert_eq!(outcome.metadata.account.as_deref(), Some("acct_from_flag"));
    }

    #[test]
    fn state_mismatch_is_csrf_denied_without_exchange() {
        let _g = issue_audit_guard();
        // No stub is contacted: a CSRF mismatch must refuse before the exchange.
        let http = reqwest::blocking::Client::new();
        let ep = endpoints("http://127.0.0.1:0/v1/oauth/token".to_string());
        let browser = CapturingBrowser {
            urls: Mutex::new(Vec::new()),
        };
        let loopback = MockLoopbackListener::new("ac_code", MockStateMode::Tamper);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let err = StripeAppOAuthFlow.issue(&request(None), &deps).unwrap_err();
        assert_eq!(err, IssuanceError::ConsentDenied);
    }

    #[test]
    fn missing_client_id_is_not_supported() {
        let _g = issue_audit_guard();
        let http = reqwest::blocking::Client::new();
        let ep = endpoints("https://api.stripe.com/v1/oauth/token".to_string());
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("ac_code", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let mut req = request(None);
        req.client_id = None;
        assert!(matches!(
            StripeAppOAuthFlow.issue(&req, &deps),
            Err(IssuanceError::NotSupported { .. })
        ));
    }

    #[test]
    fn missing_developer_secret_is_not_supported() {
        let _g = issue_audit_guard();
        let http = reqwest::blocking::Client::new();
        let ep = endpoints("https://api.stripe.com/v1/oauth/token".to_string());
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("ac_code", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let mut req = request(None);
        req.client_secret = None;
        assert!(matches!(
            StripeAppOAuthFlow.issue(&req, &deps),
            Err(IssuanceError::NotSupported { .. })
        ));
    }

    #[test]
    fn non_2xx_exchange_surfaces_summarized_error() {
        let _g = issue_audit_guard();
        let (base, _seen) = spawn_stub(
            400,
            r#"{"error":"invalid_grant","error_description":"authorization code does not exist"}"#,
        );
        let http = reqwest::blocking::Client::new();
        let ep = endpoints(format!("{base}/v1/oauth/token"));
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("ac_code", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let err = StripeAppOAuthFlow.issue(&request(None), &deps).unwrap_err();
        assert!(matches!(err, IssuanceError::Exchange { status: 400, .. }));
    }

    #[test]
    fn missing_refresh_token_is_unexpected_response() {
        // A 200 body without refresh_token fails closed (no partial vault).
        let body: serde_json::Value =
            serde_json::from_str(r#"{"access_token":"sk_test_access_MOCK","token_type":"bearer"}"#)
                .unwrap();
        let err = build_stripe_outcome(&request(None), &body).unwrap_err();
        assert!(matches!(err, IssuanceError::UnexpectedResponse { .. }));
    }

    #[test]
    fn restricted_key_engine_is_not_supported_with_dashboard_link() {
        let _g = issue_audit_guard();
        let http = reqwest::blocking::Client::new();
        let ep = endpoints("https://api.stripe.com/v1/oauth/token".to_string());
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("unused", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let err = StripeRestrictedKeyFlow
            .issue(&request(None), &deps)
            .unwrap_err();
        match err {
            IssuanceError::NotSupported { reason } => {
                assert!(reason.contains("dashboard.stripe.com"));
                assert!(reason.contains("grant add stripe"));
            }
            other => panic!("expected NotSupported, got {other:?}"),
        }
        assert_eq!(StripeRestrictedKeyFlow.grant_type(), GrantType::Manual);
    }

    #[test]
    fn authorize_url_encodes_and_appends_query() {
        let url = build_query_url(
            "https://marketplace.stripe.com/oauth/v2/authorize",
            &[
                ("response_type", "code"),
                ("state", "ab+c/d"),
                ("redirect_uri", "http://127.0.0.1:5000/callback"),
                ("scope", ""),
            ],
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=ab%2Bc%2Fd"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback"));
        assert!(!url.contains("scope="));
    }
}
