//! Vercel connectable-account Integration — "Phantom for Vercel".
//!
//! [`VercelIntegrationFlow`] runs the ONE human "Add Integration" click and
//! exchanges the resulting one-time code for a **non-expiring, team-scoped
//! access token** (Vercel's *app-identity* grant). It mirrors
//! [`super::github_app::GithubAppManifestFlow`]'s loopback code capture: bind an
//! ephemeral `127.0.0.1` listener, open the hosted install page, capture the
//! redirect `?code=…&state=…`, verify the CSRF `state`, then exchange the code
//! at `POST /v2/oauth/access_token`. The token is the durable root; it is
//! returned only via [`IssuanceOutcome`] for the CLI to vault, and is **never**
//! logged, printed, emitted in `--json`, or carried in an MCP response.
//!
//! # Why an Integration, not the device grant
//!
//! Vercel's `device_code` grant is empirically closed to third-party clients
//! (Dynamic Client Registration strips it; verified 2026-08-18), and reusing the
//! first-party CLI `client_id` would be unsanctioned impersonation. The
//! connectable-account Integration is the only sanctioned app-identity path: a
//! self-serve "Create Integration" form (one-time, no Vercel review below 500
//! installs) yields a `client_id`/`client_secret`; every user/team then installs
//! with one authorize click.
//!
//! # teamId plumbing
//!
//! A team install returns `team_id` in the exchange body (`null` = personal
//! account); an explicit `--team` overrides it. The team id is **not** a secret:
//! it lands in [`IssuanceMetadata::account`] and in the `rotation_provider`
//! block's `account_id`, so every subsequent team-scoped REST call
//! (`?teamId=…`) — including `phantom rotate` and whoami — is correctly scoped.
//! A missing teamId on a team install is the documented cause of Vercel 403s.
//!
//! The shipped [`crate::rotation_provider::VercelRotationProvider`] self-rotation
//! (mint child user tokens off a raw dashboard PAT) stays the fallback for the
//! rare case a raw user token is genuinely required; this flow's token is
//! non-expiring, so renewal is a no-op by construction.

use zeroize::Zeroizing;

use super::{
    guard_mock_issuance, random_state, ConsentEngine, GrantType, IssuanceDeps, IssuanceError,
    IssuanceMetadata, IssuanceOutcome, IssuanceRequest, IssuedMaterial, MaterialKind,
};
use crate::rotation_provider::{summarize_error_body, RotationProviderConfig};

/// Fixed vault name the scoped Integration token is stored under. Contains
/// `VERCEL` and `TOKEN` so [`crate::rotation_provider::VercelRotationProvider`]
/// matches it and `phantom rotate --name VERCEL_INTEGRATION_TOKEN` dispatches.
pub const VERCEL_INTEGRATION_TOKEN_NAME: &str = "VERCEL_INTEGRATION_TOKEN";

/// Consent window for the "Add Integration" click (matches the other engines).
const CONSENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The Vercel Integration consent engine (grant type `AppIdentity`).
pub struct VercelIntegrationFlow;

impl ConsentEngine for VercelIntegrationFlow {
    fn name(&self) -> &str {
        "vercel-integration"
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
        // when mock issuance is explicitly enabled. This stops a prompt-injected
        // agent from redirecting the exchange — and the token it yields — to an
        // attacker-controlled host.
        if deps.endpoints.is_overridden() {
            guard_mock_issuance()?;
        }

        // The Integration is a confidential client: both halves come from the
        // integration's Credentials section (never read from disk — the secret
        // was resolved from an env var by the CLI and handed in as Zeroizing).
        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| IssuanceError::NotSupported {
                reason: "vercel-integration requires --client-id (the Integration's Client ID \
                         from the Vercel Integrations Console)"
                    .to_string(),
            })?;
        let client_secret =
            req.client_secret
                .as_ref()
                .ok_or_else(|| IssuanceError::NotSupported {
                    reason: "vercel-integration requires --client-secret-env (the Integration's \
                             Client Secret; never read from disk)"
                        .to_string(),
                })?;
        if deps.endpoints.authorize.is_empty() || deps.endpoints.token.is_empty() {
            return Err(IssuanceError::NotSupported {
                reason: "no install/token endpoint is known for vercel-integration".to_string(),
            });
        }

        // 1. Loopback listener on 127.0.0.1:0 (RFC 8252 §7.3).
        let binding = deps.loopback.bind()?;
        let state = random_state();

        // 2. Open the hosted install page. Vercel redirects the one-time code
        //    back to the loopback `/callback`. The URL carries a `state` (CSRF)
        //    and the loopback `redirect_uri`, no secret.
        let install_url = build_install_url(
            &deps.endpoints.authorize,
            &[
                ("state", state.as_str()),
                ("redirect_uri", binding.redirect_uri.as_str()),
            ],
        );
        deps.browser.open(&install_url);
        eprintln!("Open this URL to connect the Vercel Integration: {install_url}");

        // 3. Capture the redirect code (Zeroizing), verify CSRF state.
        let captured = deps.loopback.wait(&state, None, CONSENT_TIMEOUT)?;
        if captured.state != state {
            return Err(IssuanceError::ConsentDenied);
        }
        let code = captured.code; // Zeroizing<String>

        // 4. Exchange the one-time code for the non-expiring scoped token.
        let form: Vec<(&str, &str)> = vec![
            ("client_id", client_id),
            ("client_secret", client_secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", binding.redirect_uri.as_str()),
        ];
        let response = deps
            .http
            .post(&deps.endpoints.token)
            .header("Accept", "application/json")
            .header("User-Agent", "phantom-secrets/0.1")
            .form(&form)
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

        build_integration_outcome(req, &body)
    }
}

/// Turn a successful `/v2/oauth/access_token` body into a vaultable outcome.
///
/// The `access_token` is the durable, non-expiring root (kept in `Zeroizing`,
/// never rendered). `team_id` (non-secret) prefers an explicit `--team`
/// override, else the exchange body (`null` = personal account); it plumbs
/// through to `account_id` so team-scoped REST calls are correctly scoped.
fn build_integration_outcome(
    req: &IssuanceRequest,
    body: &serde_json::Value,
) -> Result<IssuanceOutcome, IssuanceError> {
    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::UnexpectedResponse {
            reason: "token response has no access_token — the Vercel Integration exchange must \
                     return a scoped access token"
                .to_string(),
        })?;
    let access_token = Zeroizing::new(access_token.to_string());

    // teamId is NOT a secret. Explicit --team wins; else the exchange body's
    // team_id (null/absent = personal account).
    let response_team = body
        .get("team_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let team_id = req.team_id.clone().or(response_team);

    let material = IssuedMaterial {
        phm_name: VERCEL_INTEGRATION_TOKEN_NAME.to_string(),
        value: access_token,
        kind: MaterialKind::AccessToken,
        sensitive: true,
    };

    // Write the rotation_provider block so `phantom rotate --name
    // VERCEL_INTEGRATION_TOKEN` dispatches to the shipped Vercel provider with
    // the right teamId. The Integration token is non-expiring, so renewal is a
    // no-op by construction; a raw dashboard user-token seed re-enables true
    // self-rotation via the same provider.
    let rotation_config = RotationProviderConfig {
        provider: "vercel".to_string(),
        api_key_env: Some(VERCEL_INTEGRATION_TOKEN_NAME.to_string()),
        account_id: team_id.clone(),
        region: None,
        timeout_secs: 30,
        enabled: true,
    };

    let mut notes = Vec::new();
    match team_id.as_deref() {
        Some(team) => notes.push(format!(
            "Team-scoped install ({team}); teamId is applied to every REST call. \
             The token is non-expiring — renewal is a no-op."
        )),
        None => notes.push(
            "Personal-account install; the token is non-expiring — renewal is a no-op. \
             Pass --team <id> to scope a team install."
                .to_string(),
        ),
    }
    notes.push(
        "For a genuinely self-rotating raw user token, seed VercelRotationProvider with a \
         dashboard PAT instead."
            .to_string(),
    );

    let metadata = IssuanceMetadata {
        display_name: "Phantom for Vercel".to_string(),
        account: team_id,
        scopes: req.scopes.clone(),
        notes,
        ..Default::default()
    };

    Ok(IssuanceOutcome {
        provider: "vercel".to_string(),
        grant_type: GrantType::AppIdentity,
        materials: vec![material],
        rotation_config,
        metadata,
    })
}

/// Build `base?k=v&…`, percent-encoding each value and skipping empty ones.
fn build_install_url(base: &str, params: &[(&str, &str)]) -> String {
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
    /// the pkce/device/audit tests use; poison-tolerant so one panicking test
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

    fn endpoints(token: String) -> Endpoints {
        Endpoints {
            github_web: String::new(),
            github_api: String::new(),
            authorize: "https://vercel.com/integrations/phantom/new".to_string(),
            token,
            device_code: String::new(),
            overridden: true, // exercises the mock gate (allowed under cfg(test))
        }
    }

    fn request(team_id: Option<&str>) -> IssuanceRequest {
        IssuanceRequest {
            provider: "vercel-integration".to_string(),
            client_id: Some("phantom_client_id".to_string()),
            client_secret: Some(Zeroizing::new("integration_secret_MOCK".to_string())),
            scopes: vec!["project".to_string(), "project-env-vars".to_string()],
            flow: None,
            app_manifest: None,
            team_id: team_id.map(str::to_string),
            account: None,
            org: None,
        }
    }

    fn run(req: &IssuanceRequest, token_url: String) -> (IssuanceOutcome, Vec<String>) {
        let http = reqwest::blocking::Client::new();
        let ep = endpoints(token_url);
        let browser = CapturingBrowser {
            urls: Mutex::new(Vec::new()),
        };
        let loopback = MockLoopbackListener::new("vercel_code_123", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let outcome = VercelIntegrationFlow.issue(req, &deps).unwrap();
        let urls = browser.urls.lock().unwrap().clone();
        (outcome, urls)
    }

    #[test]
    fn team_install_vaults_scoped_token_and_plumbs_team_id() {
        let _g = issue_audit_guard();
        let (base, seen) = spawn_stub(
            200,
            r#"{"access_token":"vercel_scoped_MOCK","token_type":"Bearer","team_id":"team_abc123","installation_id":"icfg_xyz"}"#,
        );
        let req = request(None); // team comes from the exchange body
        let (outcome, urls) = run(&req, format!("{base}/v2/oauth/access_token"));

        // Durable root: the non-expiring scoped token, under the fixed name.
        assert_eq!(outcome.materials.len(), 1);
        let m = &outcome.materials[0];
        assert_eq!(m.phm_name, VERCEL_INTEGRATION_TOKEN_NAME);
        assert_eq!(m.value.as_str(), "vercel_scoped_MOCK");
        assert!(m.sensitive);
        assert_eq!(m.kind, MaterialKind::AccessToken);

        // teamId plumbs into rotation + metadata (non-secret).
        assert_eq!(outcome.provider, "vercel");
        assert_eq!(outcome.grant_type, GrantType::AppIdentity);
        assert_eq!(outcome.rotation_config.provider, "vercel");
        assert_eq!(
            outcome.rotation_config.api_key_env.as_deref(),
            Some(VERCEL_INTEGRATION_TOKEN_NAME)
        );
        assert_eq!(
            outcome.rotation_config.account_id.as_deref(),
            Some("team_abc123")
        );
        assert_eq!(outcome.metadata.account.as_deref(), Some("team_abc123"));

        // The install URL the browser saw carries a CSRF state, no secret.
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("vercel.com/integrations/phantom/new"));
        assert!(urls[0].contains("state="));
        assert!(!urls[0].contains("integration_secret_MOCK"));

        // The exchange POSTed the code + credentials, form-encoded.
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("code=vercel_code_123"));
        assert!(requests[0].contains("client_id=phantom_client_id"));

        // Redacting Debug never renders the token or the client secret.
        let dbg = format!("{outcome:?}");
        assert!(dbg.contains("[redacted]"));
        assert!(!dbg.contains("vercel_scoped_MOCK"));
    }

    #[test]
    fn explicit_team_overrides_response_team() {
        let _g = issue_audit_guard();
        let (base, _seen) = spawn_stub(
            200,
            r#"{"access_token":"vercel_scoped_MOCK","team_id":"team_from_body"}"#,
        );
        let req = request(Some("team_override")); // --team wins
        let (outcome, _urls) = run(&req, format!("{base}/v2/oauth/access_token"));
        assert_eq!(
            outcome.rotation_config.account_id.as_deref(),
            Some("team_override")
        );
        assert_eq!(outcome.metadata.account.as_deref(), Some("team_override"));
    }

    #[test]
    fn personal_install_has_no_team_id() {
        let _g = issue_audit_guard();
        // Personal account: team_id is null in the body.
        let (base, _seen) = spawn_stub(
            200,
            r#"{"access_token":"vercel_scoped_MOCK","team_id":null}"#,
        );
        let req = request(None);
        let (outcome, _urls) = run(&req, format!("{base}/v2/oauth/access_token"));
        assert_eq!(outcome.rotation_config.account_id, None);
        assert_eq!(outcome.metadata.account, None);
    }

    #[test]
    fn state_mismatch_is_csrf_denied_without_exchange() {
        let _g = issue_audit_guard();
        // No stub is contacted: a CSRF mismatch must refuse before the exchange.
        let http = reqwest::blocking::Client::new();
        let ep = endpoints("http://127.0.0.1:0/v2/oauth/access_token".to_string());
        let browser = CapturingBrowser {
            urls: Mutex::new(Vec::new()),
        };
        let loopback = MockLoopbackListener::new("code", MockStateMode::Tamper);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let err = VercelIntegrationFlow
            .issue(&request(None), &deps)
            .unwrap_err();
        assert_eq!(err, IssuanceError::ConsentDenied);
    }

    #[test]
    fn missing_client_id_is_not_supported() {
        let _g = issue_audit_guard();
        let http = reqwest::blocking::Client::new();
        let ep = endpoints("https://api.vercel.com/v2/oauth/access_token".to_string());
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
            VercelIntegrationFlow.issue(&req, &deps),
            Err(IssuanceError::NotSupported { .. })
        ));
    }

    #[test]
    fn non_2xx_exchange_surfaces_summarized_error() {
        let _g = issue_audit_guard();
        let (base, _seen) = spawn_stub(
            400,
            r#"{"error":"invalid_grant","error_description":"bad code"}"#,
        );
        let http = reqwest::blocking::Client::new();
        let ep = endpoints(format!("{base}/v2/oauth/access_token"));
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("code", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let err = VercelIntegrationFlow
            .issue(&request(None), &deps)
            .unwrap_err();
        assert!(matches!(err, IssuanceError::Exchange { status: 400, .. }));
    }

    #[test]
    fn missing_access_token_is_unexpected_response() {
        // A 200 body without access_token fails closed (no partial vault).
        let body: serde_json::Value =
            serde_json::from_str(r#"{"token_type":"Bearer","team_id":"team_x"}"#).unwrap();
        let err = build_integration_outcome(&request(None), &body).unwrap_err();
        assert!(matches!(err, IssuanceError::UnexpectedResponse { .. }));
    }

    #[test]
    fn install_url_encodes_and_appends_query() {
        let url = build_install_url(
            "https://vercel.com/integrations/phantom/new",
            &[
                ("state", "ab+c/d"),
                ("redirect_uri", "http://127.0.0.1:5000/callback"),
                ("empty", ""),
            ],
        );
        assert!(url.contains("state=ab%2Bc%2Fd"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback"));
        assert!(!url.contains("empty="));
        assert!(url.starts_with("https://vercel.com/integrations/phantom/new?"));
    }
}
