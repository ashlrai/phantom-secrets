use phantom_core::config::ServiceConfig;
use std::collections::HashMap;

/// Registry of service routes for the proxy.
/// Maps local path prefixes to target HTTPS hosts.
#[derive(Debug, Clone, Default)]
pub struct ServiceRegistry {
    /// route_prefix -> ServiceRoute
    routes: HashMap<String, ServiceRoute>,
}

/// A single service route: how to forward requests to the real API.
#[derive(Debug, Clone)]
pub struct ServiceRoute {
    /// The service name (e.g., "openai")
    pub name: String,
    /// Target scheme + host (e.g., "https://api.openai.com")
    pub target_base: String,
    /// The env var name for the secret (e.g., "OPENAI_API_KEY")
    pub secret_key: String,
    /// Which header to inject the secret into
    pub header: String,
    /// Format string for the header value ("{secret}" placeholder)
    pub header_format: String,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a registry from phantom config service definitions.
    pub fn from_config(services: &std::collections::BTreeMap<String, ServiceConfig>) -> Self {
        let mut registry = Self::new();

        for (name, config) in services {
            if let Some(pattern) = &config.pattern {
                if config.secret_type == "api_key" {
                    let target_base = format!("https://{pattern}");
                    registry.add_route(ServiceRoute {
                        name: name.clone(),
                        target_base,
                        secret_key: config.secret_key.clone(),
                        header: config
                            .header
                            .clone()
                            .unwrap_or_else(|| "Authorization".to_string()),
                        header_format: config
                            .header_format
                            .clone()
                            .unwrap_or_else(|| "Bearer {secret}".to_string()),
                    });
                }
            }
        }

        registry
    }

    /// Add a route to the registry.
    pub fn add_route(&mut self, route: ServiceRoute) {
        self.routes.insert(route.name.clone(), route);
    }

    /// Keep only the routes for which `keep` returns true.
    ///
    /// `phantom exec` and `phantom start` use this to export base-URL
    /// overrides only for routes whose credential is loaded in the current
    /// session. Pointing an SDK at a route with no vault value would turn
    /// every request into a proxy-generated 503 (for example Claude Code
    /// signed in with its own subscription while only OpenAI is protected).
    pub fn retain_routes(&mut self, mut keep: impl FnMut(&ServiceRoute) -> bool) {
        self.routes.retain(|_, route| keep(route));
    }

    /// Look up a service route by path prefix.
    /// Path format: /<service_name>/rest/of/path
    pub fn match_route<'a>(&'a self, path: &'a str) -> Option<(&'a ServiceRoute, &'a str)> {
        // Strip leading slash
        let path = path.strip_prefix('/').unwrap_or(path);

        // Find the service name (first path segment)
        let (service_name, remainder) = match path.find('/') {
            Some(pos) => (&path[..pos], &path[pos..]),
            None => (path, ""),
        };

        self.routes
            .get(service_name)
            .map(|route| (route, remainder))
    }

    /// Get all registered service names and their route info.
    pub fn services(&self) -> Vec<(&str, &ServiceRoute)> {
        self.routes
            .iter()
            .map(|(name, route)| (name.as_str(), route))
            .collect()
    }

    /// Get the header-auth-only base URL env var overrides for all services.
    /// Returns pairs of (env_var_name, local_url).
    pub fn base_url_overrides(&self, proxy_port: u16) -> Vec<(String, String)> {
        self.base_url_overrides_with_token(proxy_port, None)
    }

    /// Get base URL overrides with optional proxy token in the local path.
    ///
    /// Path-token URLs are used by the CLI for generic SDK compatibility.
    /// Use `base_url_overrides` plus the `x-phantom-proxy-token` request
    /// header for strict header-only clients.
    pub fn base_url_overrides_with_token(
        &self,
        proxy_port: u16,
        proxy_token: Option<&str>,
    ) -> Vec<(String, String)> {
        let mut overrides = Vec::new();

        for (name, route) in &self.routes {
            let local_url = match proxy_token {
                Some(token) => format!(
                    "http://127.0.0.1:{}/{}/_phantom/{}/",
                    proxy_port, name, token
                ),
                None => format!("http://127.0.0.1:{}/{}", proxy_port, name),
            };
            // Convention: SERVICE_NAME_BASE_URL, plus the variable the
            // official SDK for this upstream actually reads when it differs.
            overrides.push((
                route_override_env_name(name, &route.secret_key),
                local_url.clone(),
            ));
            for alias in sdk_base_url_env_aliases(&route.target_base) {
                overrides.push(((*alias).to_string(), local_url.clone()));
            }
        }

        overrides
    }

    /// Every environment variable used by a built-in route override. Child
    /// processes must remove these inherited values before selectively adding
    /// the overrides for the current authenticated proxy session.
    pub fn known_override_env_names() -> &'static [&'static str] {
        &[
            "OPENAI_BASE_URL",
            "ANTHROPIC_BASE_URL",
            "STRIPE_BASE_URL",
            "STRIPE_PUBLISHABLE_BASE_URL",
            "SUPABASE_SERVICE_ROLE_BASE_URL",
            "SUPABASE_ANON_BASE_URL",
            "RESEND_BASE_URL",
            "SENDGRID_BASE_URL",
            "TWILIO_AUTH_TOKEN_BASE_URL",
            "CLOUDFLARE_API_TOKEN_BASE_URL",
            "GITHUB_TOKEN_BASE_URL",
            "PINECONE_BASE_URL",
            "REPLICATE_API_TOKEN_BASE_URL",
            "XAI_BASE_URL",
            "MISTRAL_BASE_URL",
            "PERPLEXITY_BASE_URL",
            "COHERE_BASE_URL",
            "HUGGINGFACE_BASE_URL",
            "GEMINI_BASE_URL",
            "GOOGLE_GEMINI_BASE_URL",
            "CO_API_URL",
            "REPLICATE_BASE_URL",
        ]
    }
}

/// Base-URL variables read by official SDKs whose name does not follow the
/// `<SECRET_STEM>_BASE_URL` convention. Only upstreams whose SDK treats the
/// variable as the host root (so `/<service>/` maps onto it exactly) belong
/// here; SDKs that expect a versioned path such as `/client/v4` do not.
///
/// - `google-genai` (Python and JS, Gemini CLI): `GOOGLE_GEMINI_BASE_URL`
/// - `cohere` (Python v5+): `CO_API_URL`
/// - `replicate` (Python): `REPLICATE_BASE_URL`
fn sdk_base_url_env_aliases(target_base: &str) -> &'static [&'static str] {
    match target_base {
        "https://generativelanguage.googleapis.com" => &["GOOGLE_GEMINI_BASE_URL"],
        "https://api.cohere.com" => &["CO_API_URL"],
        "https://api.replicate.com" => &["REPLICATE_BASE_URL"],
        _ => &[],
    }
}

fn route_override_env_name(name: &str, secret_key: &str) -> String {
    match name {
        "openai" => "OPENAI_BASE_URL".to_string(),
        "anthropic" => "ANTHROPIC_BASE_URL".to_string(),
        _ => format!(
            "{}_BASE_URL",
            secret_key
                .trim_end_matches("_API_KEY")
                .trim_end_matches("_SECRET_KEY")
                .trim_end_matches("_KEY")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> ServiceRegistry {
        let mut registry = ServiceRegistry::new();
        registry.add_route(ServiceRoute {
            name: "openai".to_string(),
            target_base: "https://api.openai.com".to_string(),
            secret_key: "OPENAI_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
        });
        registry.add_route(ServiceRoute {
            name: "anthropic".to_string(),
            target_base: "https://api.anthropic.com".to_string(),
            secret_key: "ANTHROPIC_API_KEY".to_string(),
            header: "x-api-key".to_string(),
            header_format: "{secret}".to_string(),
        });
        registry
    }

    #[test]
    fn test_match_route_with_path() {
        let registry = test_registry();
        let (route, remainder) = registry.match_route("/openai/v1/chat/completions").unwrap();
        assert_eq!(route.name, "openai");
        assert_eq!(remainder, "/v1/chat/completions");
    }

    #[test]
    fn test_match_route_no_trailing_path() {
        let registry = test_registry();
        let (route, remainder) = registry.match_route("/anthropic").unwrap();
        assert_eq!(route.name, "anthropic");
        assert_eq!(remainder, "");
    }

    #[test]
    fn test_match_route_unknown() {
        let registry = test_registry();
        assert!(registry.match_route("/unknown/path").is_none());
    }

    #[test]
    fn test_base_url_overrides() {
        let registry = test_registry();
        let overrides = registry.base_url_overrides(54321);
        assert!(overrides
            .iter()
            .any(|(k, v)| k == "OPENAI_BASE_URL" && v == "http://127.0.0.1:54321/openai"));
        assert!(overrides
            .iter()
            .any(|(k, v)| k == "ANTHROPIC_BASE_URL" && v == "http://127.0.0.1:54321/anthropic"));
    }

    #[test]
    fn sdk_specific_base_url_variables_point_at_the_same_route() {
        let config = phantom_core::config::PhantomConfig::new_with_defaults("p".to_string());
        let registry = ServiceRegistry::from_config(&config.services);
        let overrides = registry.base_url_overrides(54321);
        let url_for = |var: &str| {
            overrides
                .iter()
                .find(|(k, _)| k == var)
                .map(|(_, v)| v.as_str())
        };
        // Each SDK-specific name must carry the same URL as the route's
        // conventional variable, and every exported name must be in the
        // inherited-value scrub list.
        for (alias, conventional) in [
            ("GOOGLE_GEMINI_BASE_URL", "GEMINI_BASE_URL"),
            ("CO_API_URL", "COHERE_BASE_URL"),
            ("REPLICATE_BASE_URL", "REPLICATE_API_TOKEN_BASE_URL"),
        ] {
            assert!(url_for(alias).is_some(), "{alias} missing");
            assert_eq!(url_for(alias), url_for(conventional), "{alias}");
        }
        for (name, _) in &overrides {
            assert!(
                ServiceRegistry::known_override_env_names().contains(&name.as_str()),
                "{name} is exported but not scrubbed from inherited env"
            );
        }
    }

    #[test]
    fn retain_routes_drops_uncredentialed_overrides() {
        let mut registry = test_registry();
        registry.retain_routes(|route| route.secret_key == "OPENAI_API_KEY");
        let names: Vec<String> = registry
            .base_url_overrides(1)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(names, vec!["OPENAI_BASE_URL".to_string()]);
        assert!(registry.match_route("/anthropic/v1/messages").is_none());
    }

    #[test]
    fn test_base_url_overrides_with_token() {
        let registry = test_registry();
        let overrides = registry.base_url_overrides_with_token(54321, Some("proxy-token"));
        assert!(overrides.iter().any(|(k, v)| k == "OPENAI_BASE_URL"
            && v == "http://127.0.0.1:54321/openai/_phantom/proxy-token/"));
        assert!(overrides.iter().any(|(k, v)| k == "ANTHROPIC_BASE_URL"
            && v == "http://127.0.0.1:54321/anthropic/_phantom/proxy-token/"));
    }
}
