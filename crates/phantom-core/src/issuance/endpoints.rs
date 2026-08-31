//! Provider endpoint resolution for credential issuance.
//!
//! Shipped builds use only the compile-time production allowlist below. There
//! is deliberately no environment-variable override: OAuth authorization
//! codes, PKCE verifiers, client secrets, and durable refresh tokens must never
//! be redirectable by an agent-controlled process environment.
//!
//! Unit tests inject loopback endpoints through a constructor compiled only
//! under `cfg(test)`.

use super::IssuanceError;

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
    /// Test-only marker that requires the mock guard before network use. The
    /// field itself is absent from shipped library builds.
    #[cfg(test)]
    pub(crate) overridden: bool,
}

impl Endpoints {
    /// Resolve the fixed production endpoints for `provider`.
    ///
    /// Known providers (`github`, `github-app`, `supabase`, `sentry`) get
    /// sensible production defaults. Unknown providers require the relevant
    /// defaults (else the OAuth URLs stay empty and the engine reports
    /// [`IssuanceError::NotSupported`]).
    pub fn for_provider(provider: &str) -> Result<Self, IssuanceError> {
        let (github_web, github_api, authorize, token, device_code) = defaults_for(provider);

        Ok(Self {
            github_web,
            github_api,
            authorize,
            token,
            device_code,
            #[cfg(test)]
            overridden: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn is_overridden(&self) -> bool {
        self.overridden
    }

    #[cfg(not(test))]
    pub(crate) fn is_overridden(&self) -> bool {
        false
    }

    /// Inject deterministic endpoints for hermetic unit tests. This constructor
    /// and the ability to set `overridden` do not exist in shipped builds.
    #[cfg(test)]
    pub(crate) fn for_test(
        github_web: impl Into<String>,
        github_api: impl Into<String>,
        authorize: impl Into<String>,
        token: impl Into<String>,
        device_code: impl Into<String>,
    ) -> Self {
        Self {
            github_web: github_web.into(),
            github_api: github_api.into(),
            authorize: authorize.into(),
            token: token.into(),
            device_code: device_code.into(),
            overridden: true,
        }
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
        // Connectable-account Integration ("Phantom for Vercel"): `authorize`
        // is the hosted install page the human clicks "Add Integration" on;
        // `token` is the one-time code-exchange endpoint. Deliberately NO device
        // grant — Vercel's device_code grant is closed to third-party clients
        // (DCR strips it), so it stays empty and the engine never offers it.
        "vercel" | "vercel-integration" => (
            github_web,
            github_api,
            "https://vercel.com/integrations/phantom/new".to_string(),
            "https://api.vercel.com/v2/oauth/access_token".to_string(),
            String::new(),
        ),
        // Stripe App OAuth (`stripe_api_access_type=oauth`): `authorize` is the
        // Stripe marketplace install page the human clicks "accept permissions"
        // on; `token` is the code / refresh exchange, authenticated with the
        // app developer's own Stripe secret key (HTTP Basic). No device grant —
        // Stripe exposes none (verified 2026-08).
        "stripe" => (
            github_web,
            github_api,
            "https://marketplace.stripe.com/oauth/v2/authorize".to_string(),
            "https://api.stripe.com/v1/oauth/token".to_string(),
            String::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_production_github() {
        let ep = Endpoints::for_provider("github-app").unwrap();
        assert_eq!(ep.github_api, "https://api.github.com");
        assert_eq!(ep.github_web, "https://github.com");
        assert!(!ep.is_overridden());
    }

    #[test]
    fn agent_controlled_legacy_override_environment_is_ignored() {
        let _g = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PHANTOM_GITHUB_API_BASE", "https://attacker.invalid");
        std::env::set_var("PHANTOM_OAUTH_TOKEN_BASE", "https://attacker.invalid/token");
        let ep = Endpoints::for_provider("github-app").unwrap();
        std::env::remove_var("PHANTOM_GITHUB_API_BASE");
        std::env::remove_var("PHANTOM_OAUTH_TOKEN_BASE");
        assert_eq!(ep.github_api, "https://api.github.com");
        assert_eq!(ep.token, "https://github.com/login/oauth/access_token");
        assert!(!ep.is_overridden());
    }

    #[test]
    fn unit_tests_can_inject_local_endpoints() {
        let ep = Endpoints::for_test(
            "http://127.0.0.1:4100",
            "http://127.0.0.1:4101",
            "http://127.0.0.1:4102/authorize",
            "http://127.0.0.1:4102/token",
            "http://127.0.0.1:4102/device",
        );
        assert_eq!(ep.github_api, "http://127.0.0.1:4101");
        assert!(ep.is_overridden());
    }
}
