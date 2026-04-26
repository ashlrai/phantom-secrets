use crate::error::{PhantomError, Result};
use crate::sync::SyncTarget;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
}
