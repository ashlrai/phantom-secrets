use phantom_core::config::ServiceConfig;
use std::borrow::Cow;
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
    /// Version path the provider's official SDK keeps in its default base
    /// URL (e.g. `/v1` for `https://api.openai.com/v1`), or `None` when the
    /// SDK appends the full versioned path itself. See [`sdk_base_path_for`].
    pub sdk_base_path: Option<String>,
}

/// Upstream hosts whose official SDK default base URL carries a version path.
///
/// `phantom exec` exports `<SERVICE>_BASE_URL=http://127.0.0.1:P/<service>/...`
/// without that version segment, so an SDK that treats the base URL as the
/// versioned root requests `<base>/chat/completions` and would otherwise reach
/// `https://<host>/chat/completions` (404). Each entry is listed only when
/// every documented endpoint on the host lives under the path, so prefixing an
/// unversioned request can never redirect a valid call.
///
/// Hosts left out on purpose:
/// - `api.anthropic.com`: the Anthropic SDK appends `/v1/messages` itself.
/// - `api.perplexity.ai`: the OpenAI-compatible root is unversioned
///   (`https://api.perplexity.ai/chat/completions`).
/// - `api.cohere.com`: the SDK appends `/v1` or `/v2` per endpoint.
/// - `generativelanguage.googleapis.com`: the Gemini SDK appends `/v1beta`
///   (or `/v1`) itself and the OpenAI-compatible root is `/v1beta/openai`.
/// - `api-inference.huggingface.co`, `api.stripe.com`, `supabase.co`,
///   `api.resend.com`, `api.sendgrid.com`, `api.twilio.com`,
///   `api.cloudflare.com`, `api.github.com`, `pinecone.io`: their SDKs send
///   full paths from an unversioned host root.
const SDK_BASE_PATHS: &[(&str, &str)] = &[
    // OpenAI SDKs and Codex: default `https://api.openai.com/v1`.
    ("api.openai.com", "/v1"),
    // xAI documents `https://api.x.ai/v1` as the OpenAI SDK base URL.
    ("api.x.ai", "/v1"),
    // OpenAI SDK base `https://api.mistral.ai/v1`; the native `mistralai`
    // SDK uses the host root and sends `/v1/...`, which is left unchanged.
    ("api.mistral.ai", "/v1"),
    // replicate-javascript defaults to `https://api.replicate.com/v1`; the
    // Python SDK uses the host root and sends `/v1/...`, left unchanged.
    ("api.replicate.com", "/v1"),
];

/// The SDK base path for an upstream host (no scheme), if it has one.
pub fn sdk_base_path_for(host: &str) -> Option<&'static str> {
    SDK_BASE_PATHS
        .iter()
        .find(|(known, _)| *known == host)
        .map(|(_, path)| *path)
}

impl ServiceRoute {
    /// Path to request upstream for the remainder after `/<service>`.
    ///
    /// When the route has an [`sdk_base_path`](Self::sdk_base_path), an
    /// unversioned remainder gets that prefix so SDKs that treat the base URL
    /// as the versioned root reach the real endpoint. A remainder that already
    /// starts with the prefix is unchanged, so clients sending `/v1/...`
    /// explicitly never get `/v1/v1`. Every route also collapses the leading
    /// `//` produced when a caller appends `/v1/...` to the slash-terminated
    /// SDK base URL. The remainder never carries the query string; the caller
    /// splits it off first.
    pub fn upstream_path<'a>(&self, remainder: &'a str) -> Cow<'a, str> {
        let trimmed = remainder.trim_start_matches('/');
        let collapsed: Cow<'a, str> = if remainder.len() - trimmed.len() > 1 {
            Cow::Owned(format!("/{trimmed}"))
        } else {
            Cow::Borrowed(remainder)
        };
        let Some(base) = self
            .sdk_base_path
            .as_deref()
            .map(|path| path.trim_matches('/'))
            .filter(|path| !path.is_empty())
        else {
            return collapsed;
        };
        if trimmed.is_empty() {
            return collapsed;
        }
        let already_prefixed = trimmed
            .strip_prefix(base)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
        if already_prefixed {
            return collapsed;
        }
        Cow::Owned(format!("/{base}/{trimmed}"))
    }
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
                        sdk_base_path: sdk_base_path_for(pattern).map(str::to_string),
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
            // Convention: SERVICE_NAME_BASE_URL or SERVICE_NAME_API_BASE
            // We support the most common patterns
            let env_var = route_override_env_name(name, &route.secret_key);

            let local_url = match proxy_token {
                Some(token) => format!(
                    "http://127.0.0.1:{}/{}/_phantom/{}/",
                    proxy_port, name, token
                ),
                None => format!("http://127.0.0.1:{}/{}", proxy_port, name),
            };
            overrides.push((env_var, local_url));
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
        ]
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
            sdk_base_path: Some("/v1".to_string()),
        });
        registry.add_route(ServiceRoute {
            name: "anthropic".to_string(),
            target_base: "https://api.anthropic.com".to_string(),
            secret_key: "ANTHROPIC_API_KEY".to_string(),
            header: "x-api-key".to_string(),
            header_format: "{secret}".to_string(),
            sdk_base_path: None,
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

    /// Every trusted built-in route, built the same way `phantom exec` does.
    fn builtin_registry() -> ServiceRegistry {
        let services = [
            "openai",
            "anthropic",
            "stripe",
            "stripe_pub",
            "supabase",
            "supabase_anon",
            "resend",
            "sendgrid",
            "twilio",
            "cloudflare",
            "github_api",
            "pinecone",
            "replicate",
            "xai",
            "mistral",
            "perplexity",
            "cohere",
            "huggingface",
            "google_ai",
        ]
        .into_iter()
        .map(|name| {
            let config = phantom_core::config::PhantomConfig::trusted_builtin_proxy_service(name)
                .unwrap_or_else(|| panic!("{name} is a trusted built-in"));
            (name.to_string(), config)
        })
        .collect();
        ServiceRegistry::from_config(&services)
    }

    #[test]
    fn builtin_routes_carry_their_sdk_base_path() {
        let registry = builtin_registry();
        let expected: &[(&str, Option<&str>)] = &[
            ("openai", Some("/v1")),
            ("xai", Some("/v1")),
            ("mistral", Some("/v1")),
            ("replicate", Some("/v1")),
            ("anthropic", None),
            ("perplexity", None),
            ("cohere", None),
            ("google_ai", None),
            ("huggingface", None),
            ("stripe", None),
            ("stripe_pub", None),
            ("supabase", None),
            ("supabase_anon", None),
            ("resend", None),
            ("sendgrid", None),
            ("twilio", None),
            ("cloudflare", None),
            ("github_api", None),
            ("pinecone", None),
        ];
        assert_eq!(expected.len(), registry.services().len());
        for (name, path) in expected {
            let local = format!("/{name}");
            let (route, _) = registry.match_route(&local).unwrap();
            assert_eq!(route.sdk_base_path.as_deref(), *path, "route {name}");
        }
    }

    #[test]
    fn builtin_routes_map_sdk_paths_to_upstream() {
        let registry = builtin_registry();
        let cases: &[(&str, &str)] = &[
            // OpenAI-shaped SDKs append unversioned paths to the base URL.
            ("/openai/models", "https://api.openai.com/v1/models"),
            (
                "/openai/chat/completions",
                "https://api.openai.com/v1/chat/completions",
            ),
            (
                "/xai/chat/completions",
                "https://api.x.ai/v1/chat/completions",
            ),
            (
                "/mistral/chat/completions",
                "https://api.mistral.ai/v1/chat/completions",
            ),
            (
                "/replicate/predictions",
                "https://api.replicate.com/v1/predictions",
            ),
            // Callers that already send the version path are unchanged.
            (
                "/openai/v1/chat/completions",
                "https://api.openai.com/v1/chat/completions",
            ),
            ("/openai/v1", "https://api.openai.com/v1"),
            ("/xai/v1/models", "https://api.x.ai/v1/models"),
            (
                "/mistral/v1/chat/completions",
                "https://api.mistral.ai/v1/chat/completions",
            ),
            (
                "/replicate/v1/predictions",
                "https://api.replicate.com/v1/predictions",
            ),
            // `$BASE_URL/v1/...` on the slash-terminated base URL.
            ("/openai//v1/models", "https://api.openai.com/v1/models"),
            (
                "/xai//chat/completions",
                "https://api.x.ai/v1/chat/completions",
            ),
            // A segment that merely starts with `v1` is not the version path.
            (
                "/openai/v1beta/models",
                "https://api.openai.com/v1/v1beta/models",
            ),
            // The bare route is left alone.
            ("/openai", "https://api.openai.com"),
            ("/openai/", "https://api.openai.com/"),
            // SDKs that send full paths keep them (only `//` is collapsed).
            (
                "/anthropic/v1/messages",
                "https://api.anthropic.com/v1/messages",
            ),
            (
                "/anthropic//v1/messages",
                "https://api.anthropic.com/v1/messages",
            ),
            ("/anthropic/models", "https://api.anthropic.com/models"),
            (
                "/perplexity/chat/completions",
                "https://api.perplexity.ai/chat/completions",
            ),
            ("/cohere/v2/chat", "https://api.cohere.com/v2/chat"),
            (
                "/google_ai/v1beta/models",
                "https://generativelanguage.googleapis.com/v1beta/models",
            ),
            (
                "/google_ai/v1beta/openai/chat/completions",
                "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            ),
            ("/stripe/v1/charges", "https://api.stripe.com/v1/charges"),
            ("/github_api/user", "https://api.github.com/user"),
        ];
        for (local, upstream) in cases {
            let (route, remainder) = registry.match_route(local).unwrap();
            assert_eq!(
                format!("{}{}", route.target_base, route.upstream_path(remainder)),
                *upstream,
                "local path {local}"
            );
        }
    }

    #[test]
    fn custom_sdk_base_path_is_trimmed_and_matched_by_segment() {
        let route = ServiceRoute {
            name: "custom".to_string(),
            target_base: "https://example.test".to_string(),
            secret_key: "CUSTOM_API_KEY".to_string(),
            header: "Authorization".to_string(),
            header_format: "Bearer {secret}".to_string(),
            sdk_base_path: Some("/openai/v1/".to_string()),
        };
        assert_eq!(route.upstream_path("/chat"), "/openai/v1/chat");
        assert_eq!(route.upstream_path("/openai/v1/chat"), "/openai/v1/chat");
        assert_eq!(route.upstream_path("/openai/v10"), "/openai/v1/openai/v10");
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
    fn test_base_url_overrides_with_token() {
        let registry = test_registry();
        let overrides = registry.base_url_overrides_with_token(54321, Some("proxy-token"));
        assert!(overrides.iter().any(|(k, v)| k == "OPENAI_BASE_URL"
            && v == "http://127.0.0.1:54321/openai/_phantom/proxy-token/"));
        assert!(overrides.iter().any(|(k, v)| k == "ANTHROPIC_BASE_URL"
            && v == "http://127.0.0.1:54321/anthropic/_phantom/proxy-token/"));
    }
}
