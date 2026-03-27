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

    /// Get the base URL env var overrides for all services.
    /// Returns pairs of (env_var_name, local_url).
    pub fn base_url_overrides(&self, proxy_port: u16) -> Vec<(String, String)> {
        let mut overrides = Vec::new();

        for (name, route) in &self.routes {
            // Convention: SERVICE_NAME_BASE_URL or SERVICE_NAME_API_BASE
            // We support the most common patterns
            let env_var = match name.as_str() {
                "openai" => "OPENAI_BASE_URL".to_string(),
                "anthropic" => "ANTHROPIC_BASE_URL".to_string(),
                _ => format!(
                    "{}_BASE_URL",
                    route
                        .secret_key
                        .trim_end_matches("_API_KEY")
                        .trim_end_matches("_SECRET_KEY")
                        .trim_end_matches("_KEY")
                ),
            };

            let local_url = format!("http://127.0.0.1:{}/{}", proxy_port, name);
            overrides.push((env_var, local_url));
        }

        overrides
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
}
