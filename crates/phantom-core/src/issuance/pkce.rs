//! [`LoopbackPkceEngine`] — RFC 8252 loopback redirect + RFC 7636 S256 PKCE.
//!
//! The consent is a browser "Authorize" click for providers whose durable root
//! is an OAuth **refresh token** (Supabase, Sentry, GitHub user-to-server). The
//! engine binds an ephemeral `127.0.0.1` listener, opens the authorize URL,
//! captures the redirect `code`, verifies the CSRF `state`, and exchanges the
//! code (with the PKCE `code_verifier`) for the refresh token — returned only
//! via [`IssuanceOutcome`] for the CLI to vault. The value is never logged,
//! never printed, never emitted in `--json`, never carried in an MCP response.
//!
//! [`build_refresh_outcome`] is the shared "token response → [`IssuanceOutcome`]"
//! step, reused by [`super::device::DeviceFlowEngine`] so both refresh-grant
//! engines vault under identical `phm:` names and rotation config.

use base64::Engine as _;
use zeroize::Zeroizing;

use super::{
    guard_mock_issuance, random_state, ConsentEngine, GrantType, IssuanceDeps, IssuanceError,
    IssuanceMetadata, IssuanceOutcome, IssuanceRequest, IssuedMaterial, MaterialKind,
};
use crate::rotation_provider::{summarize_error_body, RotationProviderConfig};

/// Default consent window (RFC 8252 leaves this to the client; 5 min matches
/// `gh auth`). The loopback listener enforces it.
const CONSENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// RFC 8252 loopback + RFC 7636 S256 consent engine. Unit struct: all state is
/// in the injected [`IssuanceDeps`].
pub struct LoopbackPkceEngine;

impl ConsentEngine for LoopbackPkceEngine {
    fn name(&self) -> &str {
        "loopback-pkce"
    }

    fn grant_type(&self) -> GrantType {
        GrantType::OauthRefresh
    }

    fn issue(
        &self,
        req: &IssuanceRequest,
        deps: &IssuanceDeps,
    ) -> Result<IssuanceOutcome, IssuanceError> {
        // Fail closed: overridden endpoints (a non-production host) may only be
        // hit when mock issuance is explicitly enabled. This stops a
        // prompt-injected agent from redirecting the exchange — and the
        // refresh token it yields — to an attacker-controlled host.
        if deps.endpoints.overridden {
            guard_mock_issuance()?;
        }

        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| IssuanceError::NotSupported {
                reason: "the pkce flow requires --client-id (the OAuth app's client id)"
                    .to_string(),
            })?;
        if deps.endpoints.authorize.is_empty() || deps.endpoints.token.is_empty() {
            return Err(IssuanceError::NotSupported {
                reason: format!(
                    "no authorize/token endpoint is known for provider '{}'; use a known \
                     provider or set the PHANTOM_OAUTH_* endpoint overrides",
                    req.provider
                ),
            });
        }

        // ── PKCE (RFC 7636, S256 only — GitHub/Sentry reject `plain`) ────────
        let code_verifier = generate_code_verifier();
        let code_challenge = code_challenge_s256(&code_verifier);
        let state = random_state();

        // ── Loopback listener on 127.0.0.1:0 (RFC 8252 §7.3) ─────────────────
        let binding = deps.loopback.bind()?;

        // ── Authorize URL + browser launch ──────────────────────────────────
        let scope = req.scopes.join(" ");
        let authorize_url = build_authorize_url(
            &deps.endpoints.authorize,
            &[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", &binding.redirect_uri),
                ("state", &state),
                ("code_challenge", &code_challenge),
                ("code_challenge_method", "S256"),
                ("scope", &scope),
            ],
        );
        deps.browser.open(&authorize_url);
        // Exactly ONE consent artifact to stderr, so a headless user can paste
        // it. The URL carries a `state`/`code_challenge` but no secret.
        eprintln!("{authorize_url}");

        // ── Capture the redirect + verify CSRF state ─────────────────────────
        let captured = deps.loopback.wait(&state, None, CONSENT_TIMEOUT)?;
        if captured.state != state {
            // Returned state != our nonce → CSRF; refuse without exchanging.
            return Err(IssuanceError::ConsentDenied);
        }

        // ── Exchange the code (+ verifier) for the refresh token ─────────────
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", captured.code.as_str()),
            ("redirect_uri", &binding.redirect_uri),
            ("client_id", client_id),
            ("code_verifier", code_verifier.as_str()),
        ];
        // Confidential clients: the secret was resolved from an env var by the
        // caller and handed in as Zeroizing — never read from disk here.
        if let Some(secret) = req.client_secret.as_ref() {
            form.push(("client_secret", secret.as_str()));
        }

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

        // Some providers (GitHub) report failure inside a 200 body.
        if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
            return Err(map_oauth_error(err, status));
        }

        build_refresh_outcome(&req.provider, &req.scopes, &body)
    }
}

// ── Shared refresh-grant outcome builder (also used by device.rs) ───────────

/// Build the [`IssuanceOutcome`] for an OAuth **refresh** grant from a token
/// endpoint's success body — the single place both refresh-grant engines
/// (`loopback-pkce` and `device-flow`) turn a vendor token response into a
/// vaultable root. The refresh token is the durable root; the access token /
/// expiry are metadata only. The value is wrapped in `Zeroizing` and never
/// logged or printed.
///
/// `body` must be a **success** response (callers handle `error` fields first).
pub(crate) fn build_refresh_outcome(
    provider: &str,
    scopes: &[String],
    body: &serde_json::Value,
) -> Result<IssuanceOutcome, IssuanceError> {
    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::UnexpectedResponse {
            reason: "token response has no refresh_token — the provider must issue an \
                     offline/refresh token for a durable grant (request an offline scope)"
                .to_string(),
        })?;
    let refresh_token = Zeroizing::new(refresh_token.to_string());

    // Refresh-token lifetime is metadata only (never the token bytes).
    let expires_at = body
        .get("refresh_token_expires_in")
        .and_then(|v| v.as_u64())
        .map(|secs| now_unix().saturating_add(secs));

    let phm_name = refresh_token_name(provider);
    let material = IssuedMaterial {
        phm_name: phm_name.clone(),
        value: refresh_token,
        kind: MaterialKind::RefreshToken,
        sensitive: true,
    };
    let rotation_config = RotationProviderConfig {
        provider: provider.to_string(),
        api_key_env: Some(phm_name),
        enabled: true,
        ..Default::default()
    };
    let metadata = IssuanceMetadata {
        display_name: provider.to_string(),
        scopes: scopes.to_vec(),
        expires_at,
        ..Default::default()
    };

    Ok(IssuanceOutcome {
        provider: provider.to_string(),
        grant_type: GrantType::OauthRefresh,
        materials: vec![material],
        rotation_config,
        metadata,
    })
}

/// Map an OAuth `error` code to the right [`IssuanceError`].
pub(crate) fn map_oauth_error(err: &str, status: u16) -> IssuanceError {
    match err {
        "access_denied" => IssuanceError::ConsentDenied,
        other => IssuanceError::Exchange {
            status,
            // Bound the echoed code length; it is a short OAuth token, not a body.
            reason: format!("error={}", other.chars().take(64).collect::<String>()),
        },
    }
}

/// `PROVIDER_REFRESH_TOKEN`, with non-alphanumerics folded to `_`
/// (`github-app` → `GITHUB_APP_REFRESH_TOKEN`).
pub(crate) fn refresh_token_name(provider: &str) -> String {
    let sanitized: String = provider
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{sanitized}_REFRESH_TOKEN")
}

/// Current unix time in seconds (0 on a pre-epoch clock).
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 32 random bytes, base64url-nopad (43 chars — within RFC 7636's 43–128).
/// Held in `Zeroizing`; the raw bytes are scrubbed after encoding.
fn generate_code_verifier() -> Zeroizing<String> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
    zeroize::Zeroize::zeroize(&mut bytes);
    verifier
}

/// `BASE64URL_NOPAD(SHA256(code_verifier))` — the S256 challenge.
fn code_challenge_s256(code_verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(code_verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Build `base?k=v&…`, percent-encoding each value and skipping empty ones.
fn build_authorize_url(base: &str, params: &[(&str, &str)]) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let query: Vec<String> = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v)))
        .collect();
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
            authorize: "https://example.com/authorize".to_string(),
            token,
            device_code: String::new(),
            overridden: true, // exercises the mock gate (allowed under cfg(test))
        }
    }

    fn request(provider: &str, client_id: Option<&str>, scopes: Vec<String>) -> IssuanceRequest {
        IssuanceRequest {
            provider: provider.to_string(),
            client_id: client_id.map(String::from),
            client_secret: None,
            scopes,
            flow: None,
            app_manifest: None,
        }
    }

    #[test]
    fn happy_path_yields_refresh_token_and_never_prints_it() {
        let (base, seen) = spawn_stub(
            200,
            r#"{"access_token":"gho_access","refresh_token":"test_refresh_MOCK","refresh_token_expires_in":15897600}"#,
        );
        let http = reqwest::blocking::Client::new();
        let ep = endpoints(format!("{base}/token"));
        let browser = CapturingBrowser {
            urls: Mutex::new(Vec::new()),
        };
        let loopback = MockLoopbackListener::new("auth_code_123", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let req = request("github", Some("Iv1.client"), vec!["repo".to_string()]);

        let outcome = LoopbackPkceEngine.issue(&req, &deps).unwrap();

        // The durable root is the refresh token, vaulted under the right name.
        assert_eq!(outcome.materials.len(), 1);
        let m = &outcome.materials[0];
        assert_eq!(m.phm_name, "GITHUB_REFRESH_TOKEN");
        assert_eq!(m.value.as_str(), "test_refresh_MOCK");
        assert!(m.sensitive);
        assert_eq!(outcome.rotation_config.provider, "github");
        assert_eq!(
            outcome.rotation_config.api_key_env.as_deref(),
            Some("GITHUB_REFRESH_TOKEN")
        );
        assert!(outcome.metadata.expires_at.is_some());

        // The authorize URL the browser saw is S256 PKCE with a state.
        let urls = browser.urls.lock().unwrap();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("code_challenge_method=S256"));
        assert!(urls[0].contains("state="));
        assert!(urls[0].contains("code_challenge="));

        // The exchange sent our code + code_verifier.
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("grant_type=authorization_code"));
        assert!(requests[0].contains("code=auth_code_123"));
        assert!(requests[0].contains("code_verifier="));

        // Redacting Debug: the refresh token never renders.
        assert!(!format!("{outcome:?}").contains("test_refresh_MOCK"));
    }

    /// Single-response stub that answers with `status` and a `Location` header.
    /// Records whether it was ever contacted so a test can prove a redirect was
    /// (not) followed.
    fn spawn_redirect_stub(
        status: u16,
        location: &str,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hit_c = hit.clone();
        let location = location.to_string();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                hit_c.store(true, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nLocation: {location}\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        (base, hit)
    }

    /// RFC 9700: the token endpoint must not follow redirects, because the POST
    /// body carries the authorization `code` + PKCE `code_verifier` (and, for
    /// confidential clients, the `client_secret`). A 307 from the token endpoint
    /// must surface as an error, and the redirect target must never be contacted
    /// — otherwise reqwest would replay the secret-bearing body to it.
    #[test]
    fn token_endpoint_307_is_not_followed_and_body_is_not_replayed() {
        // The would-be exfil target: if the client follows the redirect it will
        // land here (and would hand back a "token"). It must stay untouched.
        let (leak_base, leak_hit) = spawn_stub(
            200,
            r#"{"refresh_token":"test_leaked_MOCK","refresh_token_expires_in":15897600}"#,
        );
        let (redirect_base, redirect_hit) = spawn_redirect_stub(307, &format!("{leak_base}/token"));

        // Build the *production* client under test — the one with the redirect
        // policy that this regression guards.
        let http = crate::issuance::build_http_client().unwrap();
        let ep = endpoints(format!("{redirect_base}/token"));
        let browser = CapturingBrowser {
            urls: Mutex::new(Vec::new()),
        };
        let loopback = MockLoopbackListener::new("auth_code_123", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let req = request("github", Some("Iv1.client"), vec!["repo".to_string()]);

        let err = LoopbackPkceEngine.issue(&req, &deps).unwrap_err();

        // The 3xx surfaces through the existing non-2xx error path…
        assert!(
            matches!(err, IssuanceError::Exchange { .. }),
            "expected Exchange error from a 307, got {err:?}"
        );
        // …the token endpoint itself was contacted…
        assert!(redirect_hit.load(std::sync::atomic::Ordering::SeqCst));
        // …but the redirect target was NEVER contacted (no body replay, no token).
        assert!(
            leak_hit.lock().unwrap().is_empty(),
            "redirect target must not receive the replayed exchange body"
        );
    }

    #[test]
    fn state_mismatch_is_csrf_denied_without_exchange() {
        // No stub needed: the exchange must not run.
        let http = reqwest::blocking::Client::new();
        let ep = endpoints("http://127.0.0.1:0/token".to_string());
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
        let req = request("sentry", Some("client"), vec![]);
        let err = LoopbackPkceEngine.issue(&req, &deps).unwrap_err();
        assert_eq!(err, IssuanceError::ConsentDenied);
    }

    #[test]
    fn missing_client_id_is_not_supported() {
        let http = reqwest::blocking::Client::new();
        let ep = endpoints("https://example.com/token".to_string());
        let browser = super::super::browser::NoBrowser;
        let loopback = MockLoopbackListener::new("code", MockStateMode::Echo);
        let deps = IssuanceDeps {
            browser: &browser,
            loopback: &loopback,
            http: &http,
            endpoints: &ep,
        };
        let req = request("supabase", None, vec![]);
        assert!(matches!(
            LoopbackPkceEngine.issue(&req, &deps),
            Err(IssuanceError::NotSupported { .. })
        ));
    }

    #[test]
    fn missing_refresh_token_is_unexpected_response() {
        // A success body without refresh_token fails closed (no partial vault).
        let body: serde_json::Value =
            serde_json::from_str(r#"{"access_token":"gho_only","token_type":"bearer"}"#).unwrap();
        let err = build_refresh_outcome("github", &["repo".to_string()], &body).unwrap_err();
        assert!(matches!(err, IssuanceError::UnexpectedResponse { .. }));
    }

    #[test]
    fn build_refresh_outcome_shapes_material_and_config() {
        let body: serde_json::Value = serde_json::from_str(
            r#"{"refresh_token":"ghr_device_root","refresh_token_expires_in":15897600}"#,
        )
        .unwrap();
        let outcome =
            build_refresh_outcome("github-app", &["contents".to_string()], &body).unwrap();
        assert_eq!(outcome.materials[0].phm_name, "GITHUB_APP_REFRESH_TOKEN");
        assert_eq!(outcome.materials[0].value.as_str(), "ghr_device_root");
        assert_eq!(outcome.grant_type, GrantType::OauthRefresh);
        assert_eq!(
            outcome.rotation_config.api_key_env.as_deref(),
            Some("GITHUB_APP_REFRESH_TOKEN")
        );
        assert!(outcome.metadata.expires_at.is_some());
    }

    #[test]
    fn s256_challenge_is_correct_for_known_vector() {
        // RFC 7636 Appendix B vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            code_challenge_s256(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn refresh_token_name_sanitizes_provider() {
        assert_eq!(refresh_token_name("github-app"), "GITHUB_APP_REFRESH_TOKEN");
        assert_eq!(refresh_token_name("supabase"), "SUPABASE_REFRESH_TOKEN");
    }

    #[test]
    fn map_oauth_error_distinguishes_denied() {
        assert_eq!(
            map_oauth_error("access_denied", 200),
            IssuanceError::ConsentDenied
        );
        assert!(matches!(
            map_oauth_error("invalid_grant", 400),
            IssuanceError::Exchange { .. }
        ));
    }
}
