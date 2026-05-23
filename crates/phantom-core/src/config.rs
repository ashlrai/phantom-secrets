use crate::error::{PhantomError, Result};
use crate::sync::SyncTarget;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

/// The `.phantom.toml` project config file.
///
/// `#[serde(deny_unknown_fields)]` is set so that typos like `patern` (vs
/// `pattern`) fail loudly at load time rather than silently disabling a
/// protection (audit F15).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhantomConfig {
    pub phantom: PhantomMeta,
    /// Service pattern mappings: service name -> ServiceConfig
    #[serde(default)]
    pub services: BTreeMap<String, ServiceConfig>,
    /// Deployment platform sync targets
    #[serde(default)]
    pub sync: Vec<SyncTarget>,
    /// Cloud sync configuration
    #[serde(default)]
    pub cloud: Option<CloudConfig>,
    /// Keys explicitly classified as public (skipped during init)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_keys: Vec<String>,
}

/// Cloud vault sync configuration.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct CloudConfig {
    /// Last synced version number (managed by CLI)
    #[serde(default)]
    pub version: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhantomMeta {
    pub version: String,
    /// Project identifier (hash of project path, for vault namespacing)
    pub project_id: String,
}

/// Configuration for how a secret maps to an API service.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// The env var name holding the secret (e.g., "OPENAI_API_KEY")
    pub secret_key: String,
    /// Host pattern to match for proxy injection (e.g., "api.openai.com")
    #[serde(default)]
    pub pattern: Option<String>,
    /// HTTP header to inject into (e.g., "Authorization")
    #[serde(default)]
    pub header: Option<String>,
    /// Format string for the header value. Use `{secret}` as placeholder.
    /// e.g., "Bearer {secret}"
    #[serde(default)]
    pub header_format: Option<String>,
    /// Type of secret: "api_key" (default) or "connection_string"
    #[serde(default = "default_secret_type")]
    pub secret_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRisk {
    pub service: String,
    pub message: String,
}

fn default_secret_type() -> String {
    "api_key".to_string()
}

impl PhantomConfig {
    /// Load config from a file path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                PhantomError::ConfigNotFound(path.display().to_string())
            } else {
                PhantomError::Io(e)
            }
        })?;
        toml::from_str(&content).map_err(|e| PhantomError::ConfigParseError(e.to_string()))
    }

    /// Save config to a file path.
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| PhantomError::ConfigParseError(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Create a new config with default service patterns and a project ID.
    pub fn new_with_defaults(project_id: String) -> Self {
        let mut services = BTreeMap::new();

        services.insert(
            "openai".to_string(),
            ServiceConfig {
                secret_key: "OPENAI_API_KEY".to_string(),
                pattern: Some("api.openai.com".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "anthropic".to_string(),
            ServiceConfig {
                secret_key: "ANTHROPIC_API_KEY".to_string(),
                pattern: Some("api.anthropic.com".to_string()),
                header: Some("x-api-key".to_string()),
                header_format: Some("{secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "stripe".to_string(),
            ServiceConfig {
                secret_key: "STRIPE_SECRET_KEY".to_string(),
                pattern: Some("api.stripe.com".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "supabase".to_string(),
            ServiceConfig {
                secret_key: "SUPABASE_SERVICE_ROLE_KEY".to_string(),
                pattern: Some("supabase.co".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "database".to_string(),
            ServiceConfig {
                secret_key: "DATABASE_URL".to_string(),
                pattern: None,
                header: None,
                header_format: None,
                secret_type: "connection_string".to_string(),
            },
        );

        // Additional first-class AI providers — every popular model API
        // ships with default routing so users don't need to hand-author
        // .phantom.toml entries for the common case.

        services.insert(
            "xai".to_string(),
            ServiceConfig {
                secret_key: "XAI_API_KEY".to_string(),
                pattern: Some("api.x.ai".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "mistral".to_string(),
            ServiceConfig {
                secret_key: "MISTRAL_API_KEY".to_string(),
                pattern: Some("api.mistral.ai".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "perplexity".to_string(),
            ServiceConfig {
                secret_key: "PERPLEXITY_API_KEY".to_string(),
                pattern: Some("api.perplexity.ai".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "cohere".to_string(),
            ServiceConfig {
                secret_key: "COHERE_API_KEY".to_string(),
                pattern: Some("api.cohere.com".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "replicate".to_string(),
            ServiceConfig {
                secret_key: "REPLICATE_API_TOKEN".to_string(),
                pattern: Some("api.replicate.com".to_string()),
                header: Some("Authorization".to_string()),
                // Replicate uses "Token <key>" not "Bearer <key>"
                header_format: Some("Token {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "huggingface".to_string(),
            ServiceConfig {
                secret_key: "HUGGINGFACE_API_KEY".to_string(),
                pattern: Some("api-inference.huggingface.co".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        services.insert(
            "google_ai".to_string(),
            ServiceConfig {
                secret_key: "GEMINI_API_KEY".to_string(),
                pattern: Some("generativelanguage.googleapis.com".to_string()),
                header: Some("x-goog-api-key".to_string()),
                header_format: Some("{secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        Self {
            phantom: PhantomMeta {
                version: "1".to_string(),
                project_id,
            },
            services,
            sync: Vec::new(),
            cloud: None,
            public_keys: Vec::new(),
        }
    }

    /// Generate a stable project ID from a directory path.
    /// Uses FNV-1a (64-bit) which is deterministic across Rust versions and platforms.
    pub fn project_id_from_path(path: &Path) -> String {
        let bytes = path.to_string_lossy().as_bytes().to_vec();
        let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
        for byte in &bytes {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3); // FNV prime
        }
        format!("{:016x}", hash)
    }

    /// Get service configs that have proxy patterns (API key type).
    pub fn proxy_services(&self) -> Vec<(&str, &ServiceConfig)> {
        self.services
            .iter()
            .filter(|(_, c)| c.pattern.is_some() && c.secret_type == "api_key")
            .map(|(name, config)| (name.as_str(), config))
            .collect()
    }

    /// Get service configs for connection strings (env var injection, not proxied).
    pub fn connection_string_services(&self) -> Vec<(&str, &ServiceConfig)> {
        self.services
            .iter()
            .filter(|(_, c)| c.secret_type == "connection_string")
            .map(|(name, config)| (name.as_str(), config))
            .collect()
    }

    /// Advisory risk analysis for service routing.
    ///
    /// This intentionally does not reject custom providers: OpenAI-compatible
    /// gateways, self-hosted inference endpoints, and private proxies are valid
    /// use cases. The goal is to make high-risk routing changes visible in
    /// doctor/check output so users review them deliberately.
    pub fn service_risks(&self) -> Vec<ConfigRisk> {
        let mut risks = Vec::new();

        for (name, service) in &self.services {
            if service.secret_type != "api_key" {
                continue;
            }

            let Some(pattern) = service.pattern.as_deref() else {
                continue;
            };
            let normalized = pattern.trim().to_ascii_lowercase();

            if normalized.contains("://")
                || normalized.contains('/')
                || normalized.contains('?')
                || normalized.contains('#')
                || normalized.contains('@')
                || normalized.contains('*')
                || normalized.is_empty()
            {
                risks.push(ConfigRisk {
                    service: name.clone(),
                    message: format!(
                        "service route pattern `{pattern}` should be a bare provider host, not a URL/path/wildcard"
                    ),
                });
            }

            if extract_host_for_risk_check(&normalized)
                .as_deref()
                .is_some_and(is_local_or_private_host)
            {
                risks.push(ConfigRisk {
                    service: name.clone(),
                    message: format!(
                        "service route pattern `{pattern}` points at localhost or a private IP"
                    ),
                });
            }

            if let Some(expected) = expected_pattern_for_service(name) {
                if normalized != expected {
                    risks.push(ConfigRisk {
                        service: name.clone(),
                        message: format!(
                            "built-in service `{name}` routes to `{pattern}` instead of expected `{expected}`"
                        ),
                    });
                }
            }

            if let Some(expected) = expected_pattern_for_secret(&service.secret_key) {
                if normalized != expected {
                    risks.push(ConfigRisk {
                        service: name.clone(),
                        message: format!(
                            "secret `{}` routes to `{pattern}` instead of expected `{expected}`",
                            service.secret_key
                        ),
                    });
                }
            }

            if service
                .header_format
                .as_deref()
                .is_some_and(|format| !format.contains("{secret}"))
            {
                risks.push(ConfigRisk {
                    service: name.clone(),
                    message: "header_format does not contain `{secret}`; proxy injection will not include the secret".to_string(),
                });
            }
        }

        risks
    }
}

fn expected_pattern_for_service(name: &str) -> Option<&'static str> {
    match name {
        "openai" => Some("api.openai.com"),
        "anthropic" => Some("api.anthropic.com"),
        "stripe" => Some("api.stripe.com"),
        "supabase" => Some("supabase.co"),
        "xai" => Some("api.x.ai"),
        "mistral" => Some("api.mistral.ai"),
        "perplexity" => Some("api.perplexity.ai"),
        "cohere" => Some("api.cohere.com"),
        "replicate" => Some("api.replicate.com"),
        "huggingface" => Some("api-inference.huggingface.co"),
        "google_ai" => Some("generativelanguage.googleapis.com"),
        _ => None,
    }
}

fn expected_pattern_for_secret(secret_key: &str) -> Option<&'static str> {
    match secret_key {
        "OPENAI_API_KEY" => Some("api.openai.com"),
        "ANTHROPIC_API_KEY" => Some("api.anthropic.com"),
        "STRIPE_SECRET_KEY" => Some("api.stripe.com"),
        "SUPABASE_SERVICE_ROLE_KEY" => Some("supabase.co"),
        "XAI_API_KEY" => Some("api.x.ai"),
        "MISTRAL_API_KEY" => Some("api.mistral.ai"),
        "PERPLEXITY_API_KEY" => Some("api.perplexity.ai"),
        "COHERE_API_KEY" => Some("api.cohere.com"),
        "REPLICATE_API_TOKEN" => Some("api.replicate.com"),
        "HUGGINGFACE_API_KEY" => Some("api-inference.huggingface.co"),
        "GEMINI_API_KEY" => Some("generativelanguage.googleapis.com"),
        _ => None,
    }
}

fn is_local_or_private_host(host: &str) -> bool {
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return true;
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
        }
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => false,
    }
}

fn extract_host_for_risk_check(pattern: &str) -> Option<String> {
    let without_scheme = pattern.split("://").last().unwrap_or(pattern);
    let without_path = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    let without_userinfo = without_path.rsplit('@').next().unwrap_or(without_path);

    if without_userinfo.starts_with('[') {
        return without_userinfo
            .split_once(']')
            .map(|(host, _)| host.trim_start_matches('[').to_string());
    }

    let host = without_userinfo
        .split(':')
        .next()
        .unwrap_or(without_userinfo)
        .trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_defaults() {
        let config = PhantomConfig::new_with_defaults("test123".to_string());
        assert_eq!(config.phantom.version, "1");
        assert_eq!(config.phantom.project_id, "test123");
        assert!(config.services.contains_key("openai"));
        assert!(config.services.contains_key("anthropic"));
        assert!(config.services.contains_key("stripe"));
        assert!(config.services.contains_key("database"));
    }

    #[test]
    fn test_proxy_services() {
        let config = PhantomConfig::new_with_defaults("test".to_string());
        let proxy = config.proxy_services();
        assert!(proxy.iter().any(|(name, _)| *name == "openai"));
        assert!(!proxy.iter().any(|(name, _)| *name == "database"));
    }

    #[test]
    fn test_connection_string_services() {
        let config = PhantomConfig::new_with_defaults("test".to_string());
        let conn = config.connection_string_services();
        assert!(conn.iter().any(|(name, _)| *name == "database"));
        assert!(!conn.iter().any(|(name, _)| *name == "openai"));
    }

    #[test]
    fn test_roundtrip_serialize() {
        let config = PhantomConfig::new_with_defaults("test".to_string());
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: PhantomConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.phantom.project_id, "test");
        assert_eq!(parsed.services.len(), config.services.len());
    }

    #[test]
    fn test_project_id_from_path() {
        let id1 = PhantomConfig::project_id_from_path(Path::new("/home/user/project-a"));
        let id2 = PhantomConfig::project_id_from_path(Path::new("/home/user/project-b"));
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 16);
    }

    #[test]
    fn test_deny_unknown_fields_on_phantom_config() {
        // Top-level typo — e.g. `[phantom]` section with an extra field
        let bad = r#"
[phantom]
version = "1"
project_id = "abc"
typo_field = "oops"
"#;
        assert!(toml::from_str::<PhantomConfig>(bad).is_err());
    }

    #[test]
    fn test_deny_unknown_fields_on_service_config() {
        // F15 hard case: a typo like `patern` (missing t) would previously
        // silently disable proxy routing for that service. Now it must fail.
        let bad = r#"
[phantom]
version = "1"
project_id = "abc"

[services.openai]
secret_key = "OPENAI_API_KEY"
patern = "api.openai.com"
header = "Authorization"
"#;
        let err = toml::from_str::<PhantomConfig>(bad)
            .expect_err("expected deny_unknown_fields to reject `patern`");
        assert!(
            err.to_string().contains("patern") || err.to_string().contains("unknown field"),
            "error should mention the bad field: {err}"
        );
    }

    #[test]
    fn test_valid_config_still_parses() {
        let config = PhantomConfig::new_with_defaults("test".to_string());
        let toml_str = toml::to_string_pretty(&config).unwrap();
        // Round-tripping our own output must never trip deny_unknown_fields.
        let parsed: PhantomConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.services.len(), config.services.len());
    }

    #[test]
    fn service_risks_allows_default_config() {
        let config = PhantomConfig::new_with_defaults("test".to_string());
        assert!(config.service_risks().is_empty());
    }

    #[test]
    fn service_risks_warns_on_builtin_reroute() {
        let mut config = PhantomConfig::new_with_defaults("test".to_string());
        config.services.get_mut("openai").unwrap().pattern =
            Some("attacker.example.com".to_string());

        let risks = config.service_risks();
        assert!(risks
            .iter()
            .any(|risk| { risk.service == "openai" && risk.message.contains("built-in service") }));
        assert!(risks
            .iter()
            .any(|risk| { risk.service == "openai" && risk.message.contains("OPENAI_API_KEY") }));
    }

    #[test]
    fn service_risks_warns_on_url_like_patterns_private_hosts_and_bad_header_format() {
        let mut config = PhantomConfig::new_with_defaults("test".to_string());
        config.services.insert(
            "custom".to_string(),
            ServiceConfig {
                secret_key: "CUSTOM_API_KEY".to_string(),
                pattern: Some("https://127.0.0.1:8080/path?x=1".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer TOKEN".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        let risks = config.service_risks();
        let custom: Vec<&ConfigRisk> = risks
            .iter()
            .filter(|risk| risk.service == "custom")
            .collect();
        assert!(custom
            .iter()
            .any(|risk| risk.message.contains("bare provider host")));
        assert!(custom
            .iter()
            .any(|risk| risk.message.contains("localhost or a private IP")));
        assert!(custom
            .iter()
            .any(|risk| risk.message.contains("header_format")));
    }

    #[test]
    fn service_risks_allows_unknown_custom_provider() {
        let mut config = PhantomConfig::new_with_defaults("test".to_string());
        config.services.insert(
            "gateway".to_string(),
            ServiceConfig {
                secret_key: "GATEWAY_API_KEY".to_string(),
                pattern: Some("gateway.example.com".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );

        assert!(config
            .service_risks()
            .iter()
            .all(|risk| risk.service != "gateway"));
    }
}
