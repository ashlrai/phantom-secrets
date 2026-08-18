//! Sentry published-integration install flow + stateless JWT-bearer renewal.
//!
//! This mirrors the shipped GitHub installation-token architecture almost
//! verbatim: a long-lived **app identity** (the integration's `client_id` /
//! `client_secret`) is vaulted once, and short-lived **8-hour org tokens** are
//! minted on demand from it — issuance and renewal are the same operation.
//!
//! * [`SentryInstallFlow`] runs the ONE human "Accept & Install" click. It binds
//!   an ephemeral `127.0.0.1` loopback listener (RFC 8252 §7.3), opens the
//!   integration's `external-install` page, captures the redirect
//!   `?code=…&installationId=…&state=…`, verifies the CSRF `state`, and exchanges
//!   the grant code at
//!   `POST /api/0/sentry-app-installations/{uuid}/authorizations/` for the first
//!   8-hour org token. The durable root is the **app identity** (`client_secret`,
//!   which plays the GitHub-App-private-key role); the org token is the working
//!   credential that `phantom rotate` re-mints.
//! * Renewal is handled statelessly by
//!   [`crate::rotation_provider::SentryRotationProvider`] via the
//!   `urn:sentry:params:oauth:grant-type:jwt-bearer` grant — a JWT signed with
//!   `client_secret` ([`mint_install_jwt`]). There is no stored refresh token to
//!   lose; the app identity is the only persistent secret.
//!
//! # Consent transport
//!
//! Sentry delivers the grant code two ways: the redirect query params (handled
//! here, the loopback landing) **and** the `installation.created` webhook
//! payload (`data.installation.code` + `uuid`). A webhook receiver is a hosted
//! server concern out of scope for the local CLI; see `docs/grants-spec.md` for
//! the server variant. The loopback landing is the local-first path.
//!
//! # Security
//!
//! Every secret value (`client_secret`, the JWT seed, the org token, the grant
//! code) is a [`zeroize::Zeroizing`] end to end and is **never** logged, printed,
//! emitted in `--json`, or carried in an MCP response — it travels vendor → core
//! → CLI → vault only. Vendor error bodies only surface through
//! [`summarize_error_body`]. The HTTP client disables redirect-following
//! (RFC 9700), the loopback is `127.0.0.1`-only, and the CSRF `state` is checked
//! before any exchange.

use std::time::Duration;

use serde::Serialize;
use zeroize::Zeroizing;

use super::{
    guard_mock_issuance, random_state, ConsentEngine, GrantType, IssuanceDeps, IssuanceError,
    IssuanceMetadata, IssuanceOutcome, IssuanceRequest, IssuedMaterial, MaterialKind,
};
use crate::rotation_provider::{summarize_error_body, RotationProviderConfig};

/// Vault name for the JWT-bearer **seed** — the packed `client_id` +
/// `client_secret` app identity that [`crate::rotation_provider::SentryRotationProvider`]
/// signs each 8-hour org token from. Contains `SENTRY` so the provider's
/// `matches()` heuristic recognises it. Sensitive (embeds the client secret).
pub const SENTRY_APP_JWT_SEED_NAME: &str = "SENTRY_APP_JWT_SEED";
/// Vault name for the integration client id (non-sensitive; also inside the
/// seed, vaulted separately for display and manual use).
pub const SENTRY_CLIENT_ID_NAME: &str = "SENTRY_CLIENT_ID";
/// Vault name the minted 8-hour org token lands under (the rotation target).
pub const SENTRY_ORG_TOKEN_NAME: &str = "SENTRY_ORG_TOKEN";

/// Sentry installation **access** tokens expire after 8 hours.
pub const SENTRY_ORG_TOKEN_TTL_SECS: u64 = 8 * 3_600;

/// Consent window for the "Accept & Install" click (matches the other engines).
const CONSENT_TIMEOUT: Duration = Duration::from_secs(300);

/// Default integration slug used to build the `external-install` URL when the
/// caller does not pass one (via `--org <slug>`).
const DEFAULT_SLUG: &str = "phantom";

// ── Engine ──────────────────────────────────────────────────────────────────

/// The Sentry public-integration install consent engine (grant `AppIdentity`).
pub struct SentryInstallFlow;

impl ConsentEngine for SentryInstallFlow {
    fn name(&self) -> &str {
        "sentry-install"
    }

    fn grant_type(&self) -> GrantType {
        GrantType::AppIdentity
    }

    fn issue(
        &self,
        req: &IssuanceRequest,
        deps: &IssuanceDeps,
    ) -> Result<IssuanceOutcome, IssuanceError> {
        // Fail closed: an overridden (non-production) endpoint may only be hit
        // when mock issuance is explicitly enabled. Stops a prompt-injected
        // agent from redirecting the exchange — and the token it yields — to an
        // attacker-controlled host.
        if deps.endpoints.overridden {
            guard_mock_issuance()?;
        }

        // Confidential client: both halves come from the integration's
        // Developer Settings. The secret was resolved from an env var by the CLI
        // and handed in as Zeroizing — never read from disk here.
        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| IssuanceError::NotSupported {
                reason: "sentry-install requires --client-id (the integration's Client ID from \
                         Sentry > Settings > Developer Settings)"
                    .to_string(),
            })?;
        let client_secret =
            req.client_secret
                .as_ref()
                .ok_or_else(|| IssuanceError::NotSupported {
                    reason: "sentry-install requires --client-secret-env (the integration's \
                             Client Secret; never read from disk)"
                        .to_string(),
                })?;

        // The Sentry API origin (scheme://host[:port]) is derived from the OAuth
        // token endpoint, so the existing PHANTOM_OAUTH_TOKEN_BASE override seam
        // points the whole flow at a test server without a new env var.
        let origin = sentry_origin(&deps.endpoints.token);

        // `--org <slug>` names the published integration slug used to build the
        // external-install URL (carried in the shared `org` request field).
        let slug = req.org.as_deref().unwrap_or(DEFAULT_SLUG);

        // 1. Loopback listener on 127.0.0.1:0.
        let binding = deps.loopback.bind()?;
        let state = random_state();

        // 2. Open the hosted "Accept & Install" page. Sentry redirects the grant
        //    code + installationId back to the loopback `/callback`.
        let install_url = build_install_url(
            &origin,
            slug,
            &[
                ("state", state.as_str()),
                ("redirect_uri", binding.redirect_uri.as_str()),
            ],
        );
        deps.browser.open(&install_url);
        eprintln!("Open this URL to install the Phantom Sentry integration: {install_url}");

        // 3. Capture the redirect (Zeroizing code), verify CSRF state.
        let captured = deps.loopback.wait(&state, None, CONSENT_TIMEOUT)?;
        if captured.state != state {
            return Err(IssuanceError::ConsentDenied);
        }
        let installation_id = captured
            .extra
            .get("installationId")
            .filter(|s| !s.is_empty())
            .cloned()
            .ok_or_else(|| IssuanceError::UnexpectedResponse {
                reason: "the install redirect did not carry an installationId — Sentry returns \
                         it on the external-install callback (or the installation.created webhook)"
                    .to_string(),
            })?;
        let code = captured.code; // Zeroizing<String>

        // 4. Exchange the grant code for the first 8-hour org token.
        let token = exchange_install_code(
            deps,
            &origin,
            &installation_id,
            code.as_str(),
            client_id,
            client_secret.as_str(),
        )?;

        // 5. Assemble the vaultable materials. The durable root is the app
        //    identity, packed into the JWT-bearer seed the rotation provider
        //    signs from; the org token is the immediately-usable working
        //    credential + rotation target.
        let seed = pack_seed(client_id, client_secret.as_str());
        let materials = vec![
            IssuedMaterial {
                phm_name: SENTRY_APP_JWT_SEED_NAME.to_string(),
                value: seed,
                kind: MaterialKind::ClientSecret,
                sensitive: true,
            },
            IssuedMaterial {
                phm_name: SENTRY_CLIENT_ID_NAME.to_string(),
                value: Zeroizing::new(client_id.to_string()),
                kind: MaterialKind::ClientId,
                sensitive: false,
            },
            IssuedMaterial {
                phm_name: SENTRY_ORG_TOKEN_NAME.to_string(),
                value: token,
                kind: MaterialKind::AccessToken,
                sensitive: true,
            },
        ];

        // 6. rotation_provider block: renewal signs a fresh JWT from the seed and
        //    re-mints the org token against this installation uuid — stateless,
        //    no stored refresh token.
        let rotation_config = RotationProviderConfig {
            provider: "sentry".to_string(),
            api_key_env: Some(SENTRY_APP_JWT_SEED_NAME.to_string()),
            account_id: Some(installation_id.clone()),
            region: None,
            timeout_secs: 30,
            enabled: true,
        };

        let metadata = IssuanceMetadata {
            display_name: "Phantom for Sentry".to_string(),
            account: req.org.clone(),
            installation_ids: vec![installation_id],
            scopes: req.scopes.clone(),
            notes: vec![
                "8-hour org tokens renew forever via the client_secret-signed JWT-bearer grant \
                 — stateless, no stored refresh token."
                    .to_string(),
                format!(
                    "Run `phantom rotate --name {SENTRY_ORG_TOKEN_NAME}` to mint the next token."
                ),
            ],
            ..Default::default()
        };

        Ok(IssuanceOutcome {
            provider: "sentry".to_string(),
            grant_type: GrantType::AppIdentity,
            materials,
            rotation_config,
            metadata,
        })
    }
}

// ── Install-code exchange ─────────────────────────────────────────────────────

/// Exchange the one-time grant code at
/// `POST {origin}/api/0/sentry-app-installations/{uuid}/authorizations/` for the
/// first 8-hour org token. Returns only the `token` (Zeroizing); the
/// `refreshToken` is deliberately not persisted — renewal is stateless via
/// JWT-bearer.
fn exchange_install_code(
    deps: &IssuanceDeps,
    origin: &str,
    installation_id: &str,
    code: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<Zeroizing<String>, IssuanceError> {
    let url = authorizations_url(origin, installation_id);
    let body = serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
    });
    let response = deps
        .http
        .post(&url)
        .header("Accept", "application/json")
        .header("User-Agent", "phantom-secrets/0.1")
        .json(&body)
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

    let token = body.get("token").and_then(|v| v.as_str()).ok_or_else(|| {
        IssuanceError::UnexpectedResponse {
            reason: "install authorization response has no 'token' — Sentry must return the \
                     8-hour org access token"
                .to_string(),
        }
    })?;
    Ok(Zeroizing::new(token.to_string()))
}

// ── JWT-bearer minting (used by the rotation provider) ────────────────────────

/// Mint a fresh HS256 JWT from the app identity for the
/// `urn:sentry:params:oauth:grant-type:jwt-bearer` renewal grant.
///
/// `iss = client_id`, `iat = now - 60` (clock-skew slack), `exp = now + 540`
/// (<10 min); signed with `client_secret` (the shared app secret, GitHub-App
/// private-key analogue). Returned in `Zeroizing`; the caller drops it
/// immediately after the exchange. The JWT is never an env var, never on disk.
pub fn mint_install_jwt(
    client_id: &str,
    client_secret: &str,
) -> Result<Zeroizing<String>, IssuanceError> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    #[derive(Serialize)]
    struct Claims {
        iss: String,
        iat: u64,
        exp: u64,
    }

    let now = now_unix();
    let claims = Claims {
        iss: client_id.to_string(),
        iat: now.saturating_sub(60),
        exp: now + 540,
    };
    let key = EncodingKey::from_secret(client_secret.as_bytes());
    let token = encode(&Header::new(Algorithm::HS256), &claims, &key).map_err(|e| {
        IssuanceError::UnexpectedResponse {
            reason: format!("Sentry JWT signing failed: {e}"),
        }
    })?;
    Ok(Zeroizing::new(token))
}

// ── Seed pack / unpack (app identity <-> single vault secret) ─────────────────

/// Pack `client_id` + `client_secret` into a single vaultable seed. A NUL byte
/// separates them (the same packing idiom the Google rotation provider uses for
/// its challenge payload). Held in `Zeroizing` — it embeds the client secret.
pub fn pack_seed(client_id: &str, client_secret: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("{client_id}\x00{client_secret}"))
}

/// Split a packed seed back into `(client_id, client_secret)`. Returns `None`
/// when the NUL separator is absent (a malformed / legacy value).
pub fn unpack_seed(seed: &str) -> Option<(&str, &str)> {
    seed.split_once('\x00')
}

// ── URL helpers ───────────────────────────────────────────────────────────────

/// The installation authorization endpoint for `installation_id` under `origin`.
pub fn authorizations_url(origin: &str, installation_id: &str) -> String {
    format!("{origin}/api/0/sentry-app-installations/{installation_id}/authorizations/")
}

/// Reduce a full URL to its `scheme://host[:port]` origin. Used to derive the
/// Sentry API/web base from the OAuth token endpoint so the existing
/// `PHANTOM_OAUTH_TOKEN_BASE` override seam repoints the whole flow.
fn sentry_origin(token_url: &str) -> String {
    if token_url.is_empty() {
        return "https://sentry.io".to_string();
    }
    match token_url.find("://") {
        Some(scheme_end) => {
            let after = &token_url[scheme_end + 3..];
            let host_len = after.find('/').unwrap_or(after.len());
            token_url[..scheme_end + 3 + host_len].to_string()
        }
        None => token_url.trim_end_matches('/').to_string(),
    }
}

/// Build the `external-install` URL: `{origin}/sentry-apps/{slug}/external-install/?…`.
fn build_install_url(origin: &str, slug: &str, params: &[(&str, &str)]) -> String {
    let base = format!("{origin}/sentry-apps/{slug}/external-install/");
    let query: Vec<String> = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v)))
        .collect();
    if query.is_empty() {
        return base;
    }
    format!("{base}?{}", query.join("&"))
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

/// Current unix time in seconds (0 on a pre-epoch clock).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    /// the pkce/device/vercel tests use; poison-tolerant so one panicking test
    /// never cascades into the rest of the suite.
    fn issue_audit_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Capturing browser: records the install URL for assertions.
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
    /// request text so tests can assert what the engine sent, then closes.
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

    /// Endpoints whose token origin points at `stub_origin` (so the derived
    /// Sentry API base reaches the stub). `overridden` exercises the mock gate.
    fn endpoints(stub_origin: &str) -> Endpoints {
        Endpoints {
            github_web: String::new(),
            github_api: String::new(),
            authorize: format!("{stub_origin}/oauth/authorize/"),
            token: format!("{stub_origin}/oauth/token/"),
            device_code: String::new(),
            overridden: true,
        }
    }

    fn request(slug: Option<&str>) -> IssuanceRequest {
        IssuanceRequest {
            provider: "sentry".to_string(),
            client_id: Some("phantom_sentry_client".to_string()),
            client_secret: Some(Zeroizing::new("sentry_client_secret_MOCK".to_string())),
            scopes: vec!["org:read".to_string(), "project:read".to_string()],
            flow: None,
            app_manifest: None,
            team_id: None,
            account: None,
            org: slug.map(str::to_string),
        }
    }

    #[test]
    fn install_flow_vaults_app_identity_and_org_token() {
        let _g = issue_audit_guard();
        let (base, seen) = spawn_stub(
            200,
            r#"{"token":"sntrys_orgtoken_MOCK","refreshToken":"sntrys_refresh_MOCK","expiresAt":"2026-01-01T00:00:00Z","scopes":["org:read"]}"#,
        );
        let ep = endpoints(&base);
        let http = reqwest::blocking::Client::new();
        let browser = CapturingBrowser {
            urls: Mutex::new(Vec::new()),
        };
        let loopback = MockLoopbackListener::new("install_code_123", MockStateMode::Echo)
            .with_extra_param("installationId", "install-uuid-abc");
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let outcome = SentryInstallFlow
            .issue(&request(Some("phantom")), &deps)
            .unwrap();

        assert_eq!(outcome.provider, "sentry");
        assert_eq!(outcome.grant_type, GrantType::AppIdentity);

        // Durable root: the packed JWT-bearer seed (client_id + secret).
        let seed = outcome
            .materials
            .iter()
            .find(|m| m.phm_name == SENTRY_APP_JWT_SEED_NAME)
            .expect("seed material");
        assert!(seed.sensitive);
        let (cid, csec) = unpack_seed(seed.value.as_str()).unwrap();
        assert_eq!(cid, "phantom_sentry_client");
        assert_eq!(csec, "sentry_client_secret_MOCK");

        // client id vaulted separately, non-sensitive.
        let idm = outcome
            .materials
            .iter()
            .find(|m| m.phm_name == SENTRY_CLIENT_ID_NAME)
            .expect("client id material");
        assert!(!idm.sensitive);

        // The initial 8-hour org token is the working credential + rotation target.
        let tok = outcome
            .materials
            .iter()
            .find(|m| m.phm_name == SENTRY_ORG_TOKEN_NAME)
            .expect("org token material");
        assert_eq!(tok.value.as_str(), "sntrys_orgtoken_MOCK");
        assert!(tok.sensitive);
        assert_eq!(tok.kind, MaterialKind::AccessToken);

        // Rotation dispatches to the sentry provider against this installation.
        assert_eq!(outcome.rotation_config.provider, "sentry");
        assert_eq!(
            outcome.rotation_config.api_key_env.as_deref(),
            Some(SENTRY_APP_JWT_SEED_NAME)
        );
        assert_eq!(
            outcome.rotation_config.account_id.as_deref(),
            Some("install-uuid-abc")
        );
        assert_eq!(
            outcome.metadata.installation_ids,
            vec!["install-uuid-abc".to_string()]
        );

        // The install URL carries a CSRF state, no secret.
        let urls = browser.urls.lock().unwrap();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("/sentry-apps/phantom/external-install/"));
        assert!(urls[0].contains("state="));
        assert!(!urls[0].contains("sentry_client_secret_MOCK"));

        // The exchange hit the installation authorizations endpoint with the code.
        let reqs = seen.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(
            reqs[0].contains("/api/0/sentry-app-installations/install-uuid-abc/authorizations/")
        );
        assert!(reqs[0].contains("install_code_123"));
        assert!(reqs[0].contains("authorization_code"));

        // Redacting Debug never renders any secret.
        let dbg = format!("{outcome:?}");
        assert!(dbg.contains("[redacted]"));
        assert!(!dbg.contains("sntrys_orgtoken_MOCK"));
        assert!(!dbg.contains("sentry_client_secret_MOCK"));
    }

    #[test]
    fn missing_installation_id_is_unexpected_response() {
        let _g = issue_audit_guard();
        // No stub is contacted: without an installationId there is no URL to hit.
        let ep = endpoints("http://127.0.0.1:0");
        let http = reqwest::blocking::Client::new();
        let browser = super::super::browser::NoBrowser;
        // Mock loopback echoes state but carries NO installationId.
        let loopback = MockLoopbackListener::new("code", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let err = SentryInstallFlow.issue(&request(None), &deps).unwrap_err();
        assert!(matches!(err, IssuanceError::UnexpectedResponse { .. }));
    }

    #[test]
    fn state_mismatch_is_csrf_denied_without_exchange() {
        let _g = issue_audit_guard();
        let ep = endpoints("http://127.0.0.1:0");
        let http = reqwest::blocking::Client::new();
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("code", MockStateMode::Tamper)
            .with_extra_param("installationId", "uuid");
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let err = SentryInstallFlow.issue(&request(None), &deps).unwrap_err();
        assert_eq!(err, IssuanceError::ConsentDenied);
    }

    #[test]
    fn missing_client_id_is_not_supported() {
        let _g = issue_audit_guard();
        let ep = endpoints("http://127.0.0.1:0");
        let http = reqwest::blocking::Client::new();
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("code", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let mut req = request(None);
        req.client_id = None;
        assert!(matches!(
            SentryInstallFlow.issue(&req, &deps),
            Err(IssuanceError::NotSupported { .. })
        ));
    }

    #[test]
    fn non_2xx_exchange_surfaces_summarized_error() {
        let _g = issue_audit_guard();
        let (base, _seen) = spawn_stub(403, r#"{"detail":"Invalid grant","type":"error"}"#);
        let ep = endpoints(&base);
        let http = reqwest::blocking::Client::new();
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("code", MockStateMode::Echo)
            .with_extra_param("installationId", "uuid");
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let err = SentryInstallFlow.issue(&request(None), &deps).unwrap_err();
        assert!(matches!(err, IssuanceError::Exchange { status: 403, .. }));
    }

    #[test]
    fn mint_install_jwt_produces_three_part_hs256_token() {
        let jwt = mint_install_jwt("phantom_client", "shhh_secret").unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(header["alg"], "HS256");
        // iss round-trips; the secret never appears in the payload.
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["iss"], "phantom_client");
        assert!(!jwt.contains("shhh_secret"));
    }

    #[test]
    fn seed_round_trips() {
        let seed = pack_seed("cid", "csecret");
        assert_eq!(unpack_seed(seed.as_str()), Some(("cid", "csecret")));
        assert_eq!(unpack_seed("no-separator"), None);
    }

    #[test]
    fn sentry_origin_derives_from_token_url() {
        assert_eq!(
            sentry_origin("https://sentry.io/oauth/token/"),
            "https://sentry.io"
        );
        assert_eq!(
            sentry_origin("http://127.0.0.1:52100/oauth/token/"),
            "http://127.0.0.1:52100"
        );
        assert_eq!(sentry_origin(""), "https://sentry.io");
    }

    #[test]
    fn install_url_shape() {
        let url = build_install_url(
            "https://sentry.io",
            "phantom",
            &[
                ("state", "ab+c/d"),
                ("redirect_uri", "http://127.0.0.1:5000/callback"),
                ("empty", ""),
            ],
        );
        assert!(url.starts_with("https://sentry.io/sentry-apps/phantom/external-install/?"));
        assert!(url.contains("state=ab%2Bc%2Fd"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback"));
        assert!(!url.contains("empty="));
    }
}
