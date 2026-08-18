//! Base-URL resolution for issuance — production defaults with a per-provider
//! env override seam.
//!
//! This is the sole reason issuance is testable where `rotation_provider.rs`
//! (hardcoded `https://api.github.com`) is not: tests point the overrides at a
//! `wiremock::MockServer::uri()` and the whole manifest/token/device dance runs
//! against a local stub. Every override is validated **https-or-localhost**,
//! exactly like [`crate::auth::api_base_url`], so a prompt-injected agent can
//! never redirect an issuance flow to an attacker-controlled host over
//! cleartext. Any override in effect flips [`Endpoints::overridden`], which the
//! engines treat as "mock mode" and gate behind
//! [`super::issuance_mock_allowed`].

use super::IssuanceError;

/// Env var overriding the GitHub REST API base (default `https://api.github.com`).
pub const ENV_GITHUB_API_BASE: &str = "PHANTOM_GITHUB_API_BASE";
/// Env var overriding the GitHub web base (default `https://github.com`).
pub const ENV_GITHUB_WEB_BASE: &str = "PHANTOM_GITHUB_WEB_BASE";
/// Env var overriding the OAuth authorize URL.
pub const ENV_OAUTH_AUTHORIZE_BASE: &str = "PHANTOM_OAUTH_AUTHORIZE_BASE";
/// Env var overriding the OAuth token URL.
pub const ENV_OAUTH_TOKEN_BASE: &str = "PHANTOM_OAUTH_TOKEN_BASE";
/// Env var overriding the OAuth device-code URL.
pub const ENV_OAUTH_DEVICE_BASE: &str = "PHANTOM_OAUTH_DEVICE_BASE";

/// Resolved endpoints for one provider. `github_web`/`github_api` are origins
/// (call sites append paths); `authorize`/`token`/`device_code` are full URLs.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// GitHub web origin, e.g. `https://github.com`.
    pub github_web: String,
    /// GitHub REST API origin, e.g. `https://api.github.com`.
    pub github_api: String,
    /// OAuth authorize URL (empty when the provider has no PKCE flow default).
    pub authorize: String,
    /// OAuth token URL.
    pub token: String,
    /// OAuth device-code URL (empty when the provider has no device flow).
    pub device_code: String,
    /// `true` when ANY of the URLs came from an env override — i.e. mock mode.
    pub overridden: bool,
}

impl Endpoints {
    /// Resolve the endpoints for `provider`, applying any env overrides.
    ///
    /// Known providers (`github`, `github-app`, `supabase`, `sentry`) get
    /// sensible production defaults. Unknown providers require the relevant
    /// overrides (else the OAuth URLs stay empty and the engine reports
    /// [`IssuanceError::NotSupported`]).
    pub fn for_provider(provider: &str) -> Result<Self, IssuanceError> {
        let (mut github_web, mut github_api, mut authorize, mut token, mut device_code) =
            defaults_for(provider);
        let mut overridden = false;

        apply_origin_override(ENV_GITHUB_WEB_BASE, &mut github_web, &mut overridden)?;
        apply_origin_override(ENV_GITHUB_API_BASE, &mut github_api, &mut overridden)?;
        apply_full_override(ENV_OAUTH_AUTHORIZE_BASE, &mut authorize, &mut overridden)?;
        apply_full_override(ENV_OAUTH_TOKEN_BASE, &mut token, &mut overridden)?;
        apply_full_override(ENV_OAUTH_DEVICE_BASE, &mut device_code, &mut overridden)?;

        Ok(Self {
            github_web,
            github_api,
            authorize,
            token,
            device_code,
            overridden,
        })
    }
}

/// Per-provider production defaults: `(github_web, github_api, authorize, token, device_code)`.
fn defaults_for(provider: &str) -> (String, String, String, String, String) {
    let github_web = "https://github.com".to_string();
    let github_api = "https://api.github.com".to_string();
    match provider {
        "github" | "github-app" => (
            github_web,
            github_api,
            "https://github.com/login/oauth/authorize".to_string(),
            "https://github.com/login/oauth/access_token".to_string(),
            "https://github.com/login/device/code".to_string(),
        ),
        "supabase" => (
            github_web,
            github_api,
            "https://api.supabase.com/v1/oauth/authorize".to_string(),
            "https://api.supabase.com/v1/oauth/token".to_string(),
            String::new(), // Supabase exposes no device grant
        ),
        "sentry" => (
            github_web,
            github_api,
            "https://sentry.io/oauth/authorize/".to_string(),
            "https://sentry.io/oauth/token/".to_string(),
            "https://sentry.io/oauth/device/code/".to_string(),
        ),
        _ => (
            github_web,
            github_api,
            String::new(),
            String::new(),
            String::new(),
        ),
    }
}

/// Apply an origin-style override (scheme://host[:port], no path) to `slot`.
fn apply_origin_override(
    var: &str,
    slot: &mut String,
    overridden: &mut bool,
) -> Result<(), IssuanceError> {
    if let Ok(value) = std::env::var(var) {
        if value.is_empty() {
            return Ok(());
        }
        if !is_acceptable_url(&value) {
            return Err(IssuanceError::InvalidEndpoint {
                var: var.to_string(),
                value,
            });
        }
        eprintln!("phantom: {var} override in effect -> {value}");
        *slot = value.trim_end_matches('/').to_string();
        *overridden = true;
    }
    Ok(())
}

/// Apply a full-URL override to `slot`.
fn apply_full_override(
    var: &str,
    slot: &mut String,
    overridden: &mut bool,
) -> Result<(), IssuanceError> {
    if let Ok(value) = std::env::var(var) {
        if value.is_empty() {
            return Ok(());
        }
        if !is_acceptable_url(&value) {
            return Err(IssuanceError::InvalidEndpoint {
                var: var.to_string(),
                value,
            });
        }
        eprintln!("phantom: {var} override in effect -> {value}");
        *slot = value;
        *overridden = true;
    }
    Ok(())
}

/// Accept only `https://…`, `http://localhost…`, or `http://127.0.0.1…`.
///
/// Mirrors `auth::is_acceptable_api_url`, including the host-confusion guard
/// (`http://localhost.attacker.com` is rejected because it does not match the
/// bare-host / `:port` / `/path` boundaries).
fn is_acceptable_url(url: &str) -> bool {
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

    #[test]
    fn defaults_are_production_github() {
        // No overrides in this test's environment for these vars.
        for v in [
            ENV_GITHUB_API_BASE,
            ENV_GITHUB_WEB_BASE,
            ENV_OAUTH_AUTHORIZE_BASE,
            ENV_OAUTH_TOKEN_BASE,
            ENV_OAUTH_DEVICE_BASE,
        ] {
            std::env::remove_var(v);
        }
        let ep = Endpoints::for_provider("github-app").unwrap();
        assert_eq!(ep.github_api, "https://api.github.com");
        assert_eq!(ep.github_web, "https://github.com");
        assert!(!ep.overridden);
    }

    #[test]
    fn accepts_localhost_and_https_overrides() {
        assert!(is_acceptable_url("https://api.github.com"));
        assert!(is_acceptable_url("http://127.0.0.1:52100"));
        assert!(is_acceptable_url("http://localhost:8080/x"));
    }

    #[test]
    fn rejects_plain_http_and_host_confusion() {
        assert!(!is_acceptable_url("http://api.github.com"));
        assert!(!is_acceptable_url("http://127.0.0.1.attacker.com/"));
        assert!(!is_acceptable_url("http://localhost.evil.com/api"));
    }

    #[test]
    fn override_rejected_before_use() {
        let _g = crate::test_support::ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_GITHUB_API_BASE, "http://evil.example.com");
        let err = Endpoints::for_provider("github-app").unwrap_err();
        std::env::remove_var(ENV_GITHUB_API_BASE);
        assert!(matches!(err, IssuanceError::InvalidEndpoint { .. }));
    }
}
