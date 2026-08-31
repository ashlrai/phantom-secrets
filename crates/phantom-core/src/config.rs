use crate::error::{PhantomError, Result};
use crate::leak_correlation::AlertingConfig;
use crate::rotation_strategy::{RotationSchedule, RotationStrategy};
use crate::sync::SyncTarget;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    /// Machine-local namespace for vault, shadow, and scheduler state.
    ///
    /// This value is derived from the canonical directory containing
    /// `.phantom.toml` and is never accepted from or serialized into the
    /// repository-controlled config file.
    #[serde(skip)]
    local_project_id: Option<String>,
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
    /// Leak incident alerting configuration (`[alerting]` section).
    /// Controls webhook, Slack, and PagerDuty notifications for high-confidence
    /// proxy response leak incidents detected by the correlation engine.
    #[serde(default, skip_serializing_if = "alerting_is_default")]
    pub alerting: AlertingConfig,
}

fn alerting_is_default(cfg: &AlertingConfig) -> bool {
    !cfg.enabled && cfg.backends.is_empty()
}

/// Validate an identifier before it is used as a cloud/team URL component.
///
/// Generated IDs are hexadecimal. Legacy IDs may additionally use `-` and
/// `_`, but separators, URL metacharacters, whitespace, and Unicode are
/// rejected so repository config cannot alter an endpoint path or query shape.
fn validate_portable_project_id(project_id: &str) -> Result<()> {
    let valid = !project_id.is_empty()
        && project_id.len() <= 128
        && project_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));

    if valid {
        Ok(())
    } else {
        Err(PhantomError::ConfigParseError(
            "invalid portable project_id: expected 1-128 ASCII letters, digits, '-' or '_'"
                .to_string(),
        ))
    }
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
    /// Portable project identifier used by cloud and team APIs.
    ///
    /// This committed value intentionally survives clones and directory moves.
    /// Machine-local vault and state namespacing uses
    /// [`PhantomConfig::local_project_id`] instead.
    pub project_id: String,
    /// Global rotation schedule — applies to all secrets unless overridden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_policy: Option<RotationSchedule>,
    /// Per-secret configuration overrides (keyed by secret name).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretOverride>,
}

/// Validation schedule for a single secret, stored under
/// `[phantom.secrets.{name}.validation]` in `.phantom.toml`.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ValidationScheduleConfig {
    /// Whether automatic validation is enabled for this secret (default: true).
    #[serde(default = "default_validation_enabled")]
    pub enabled: bool,
    /// How often to re-validate: `"daily"`, `"weekly"`, or `"never"`.
    /// Defaults to `"daily"`.
    #[serde(default = "default_validation_schedule")]
    pub schedule: String,
    /// Per-request HTTP timeout in seconds (default: 30).
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Hint to the validator which provider to use for this secret.
    /// Accepted values: `"github"`, `"stripe"`, `"aws"`, `"openai"`,
    /// `"anthropic"`, or any custom validator name registered in the
    /// validation pipeline.  When absent the pipeline auto-selects the first
    /// validator whose `matches()` predicate returns true for the secret name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// When `true`, emit an audit event with op `"vault.validate.invalid"` and
    /// log a warning whenever a validation run transitions the secret from
    /// valid → invalid.  Defaults to `true`.
    #[serde(default = "default_alert_on_invalid")]
    pub alert_on_invalid: bool,
}

impl Default for ValidationScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            schedule: "daily".to_string(),
            timeout_secs: 30,
            provider: None,
            alert_on_invalid: true,
        }
    }
}

fn default_validation_enabled() -> bool {
    true
}

fn default_validation_schedule() -> String {
    "daily".to_string()
}

fn default_timeout_secs() -> u64 {
    30
}

fn default_alert_on_invalid() -> bool {
    true
}

impl ValidationScheduleConfig {
    /// Return the minimum number of seconds between re-validations based on
    /// the `schedule` field.  Returns `None` when schedule is `"never"`.
    pub fn interval_secs(&self) -> Option<u64> {
        match self.schedule.to_lowercase().trim() {
            "daily" => Some(86_400),
            "weekly" => Some(7 * 86_400),
            "never" => None,
            _ => Some(86_400), // unknown → default to daily
        }
    }

    /// Return `true` if the secret should be re-validated now, given the
    /// timestamp of the last check (`last_check_ts`, 0 = never checked).
    pub fn is_due(&self, last_check_ts: u64) -> bool {
        if !self.enabled {
            return false;
        }
        let Some(interval) = self.interval_secs() else {
            return false; // schedule == "never"
        };
        if last_check_ts == 0 {
            return true; // never checked
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(last_check_ts) >= interval
    }
}

/// Per-secret configuration override stored under `[phantom.secrets.{name}]`.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecretOverride {
    /// Override the global rotation schedule for this specific secret.
    /// Accepts a duration string like `"30d"`, `"7d"`, `"90d"` (days only for
    /// now) which is converted to a `Daily`/`Weekly`/`Monthly` approximation,
    /// or the caller can set a full `RotationSchedule` by using the structured
    /// `rotation_schedule` field instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_every: Option<String>,
    /// Full structured rotation schedule override (takes precedence over `rotate_every`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_schedule: Option<RotationSchedule>,
    /// Audit-log anomaly thresholds for this secret.
    /// Stored under `[phantom.secrets.{name}.audit]` in `.phantom.toml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<crate::analytics::AuditThresholdConfig>,
    /// Unix timestamp (seconds since epoch) after which this secret is expired.
    /// Set by `phantom expiry set <KEY> <DAYS>`. Used by `phantom expiry enforce`
    /// and the `phantom_expiry_enforce` MCP tool to block deployments and CI pipelines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Number of days between rotations for this secret. Used by
    /// `phantom expiry rotate <KEY>` to reset the expiry timer.
    /// Stored as `rotation_window = <DAYS>` in `.phantom.toml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_window: Option<u64>,
    /// Per-secret validation schedule configuration.
    /// Stored under `[phantom.secrets.{name}.validation]` in `.phantom.toml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationScheduleConfig>,
    /// When `true`, `phantom exec` will hard-block if this secret's
    /// `rotation_schedule` period has elapsed since `last_rotated`.
    /// The user must run `phantom rotate <NAME>` to unblock, or pass
    /// `--skip-rotation-check` (which writes an audit-log warning).
    /// Default: `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enforce_rotation_on_access: bool,
    /// Grace period (in seconds) before a secret's TTL expiry at which
    /// `phantom doctor` promotes the status from info → warning and a
    /// daily background check is emitted.
    /// Default: `604800` (7 days).
    #[serde(
        default = "default_expiry_grace_period_secs",
        skip_serializing_if = "is_default_grace"
    )]
    pub expiry_grace_period_secs: u64,
    /// Vendor-specific rotation provider configuration.
    ///
    /// When set, `phantom rotate --auto-sync` delegates rotation to the
    /// named vendor API instead of requiring a manually supplied value.
    ///
    /// Example `.phantom.toml` block:
    /// ```toml
    /// [phantom.secrets.STRIPE_SECRET_KEY.rotation_provider]
    /// provider = "stripe"
    /// api_key_env = "STRIPE_ROTATION_API_KEY"
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_provider: Option<crate::rotation_provider::RotationProviderConfig>,
}

fn is_false(b: &bool) -> bool {
    !b
}
fn default_expiry_grace_period_secs() -> u64 {
    604_800
}
fn is_default_grace(v: &u64) -> bool {
    *v == 604_800
}

impl Default for SecretOverride {
    fn default() -> Self {
        Self {
            rotate_every: None,
            rotation_schedule: None,
            audit: None,
            expires_at: None,
            rotation_window: None,
            validation: None,
            enforce_rotation_on_access: false,
            expiry_grace_period_secs: 604_800,
            rotation_provider: None,
        }
    }
}

impl SecretOverride {
    /// Resolve this override to a `RotationSchedule`, if any.
    pub fn resolve_schedule(&self) -> Option<RotationSchedule> {
        if let Some(ref sched) = self.rotation_schedule {
            return Some(sched.clone());
        }
        if let Some(ref s) = self.rotate_every {
            return parse_rotate_every(s);
        }
        None
    }
}

/// Parse a `rotate_every` string like `"30d"`, `"7d"`, `"90d"` into a
/// `RotationSchedule`.  Only day-based durations are supported.
pub fn parse_rotate_every(s: &str) -> Option<RotationSchedule> {
    let s = s.trim().to_ascii_lowercase();
    let days: u64 = s.strip_suffix('d')?.parse().ok()?;

    let strategy = if days <= 1 {
        RotationStrategy::Daily
    } else if days <= 7 {
        RotationStrategy::Weekly
    } else {
        RotationStrategy::Monthly
    };

    Some(RotationSchedule::from_strategy(strategy))
}

/// Configuration for how a secret maps to an API service.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy)]
struct TrustedProxyDefinition {
    name: &'static str,
    secret_key: &'static str,
    pattern: &'static str,
    header: &'static str,
    header_format: &'static str,
}

impl TrustedProxyDefinition {
    fn service_config(self) -> ServiceConfig {
        ServiceConfig {
            secret_key: self.secret_key.to_string(),
            pattern: Some(self.pattern.to_string()),
            header: Some(self.header.to_string()),
            header_format: Some(self.header_format.to_string()),
            secret_type: "api_key".to_string(),
        }
    }
}

/// The sole authority for repository-configurable built-in proxy routes.
///
/// Both config defaults and CLI init auto-detection consume this registry, and
/// agentic validation requires full [`ServiceConfig`] equality with an entry.
/// Keep names, destinations, headers, and formats exact: changing any one of
/// them changes the trusted network capability.
const TRUSTED_PROXY_SERVICES: &[TrustedProxyDefinition] = &[
    TrustedProxyDefinition {
        name: "openai",
        secret_key: "OPENAI_API_KEY",
        pattern: "api.openai.com",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "anthropic",
        secret_key: "ANTHROPIC_API_KEY",
        pattern: "api.anthropic.com",
        header: "x-api-key",
        header_format: "{secret}",
    },
    TrustedProxyDefinition {
        name: "stripe",
        secret_key: "STRIPE_SECRET_KEY",
        pattern: "api.stripe.com",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "stripe_pub",
        secret_key: "STRIPE_PUBLISHABLE_KEY",
        pattern: "api.stripe.com",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "supabase",
        secret_key: "SUPABASE_SERVICE_ROLE_KEY",
        pattern: "supabase.co",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "supabase_anon",
        secret_key: "SUPABASE_ANON_KEY",
        pattern: "supabase.co",
        header: "apikey",
        header_format: "{secret}",
    },
    TrustedProxyDefinition {
        name: "resend",
        secret_key: "RESEND_API_KEY",
        pattern: "api.resend.com",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "sendgrid",
        secret_key: "SENDGRID_API_KEY",
        pattern: "api.sendgrid.com",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "twilio",
        secret_key: "TWILIO_AUTH_TOKEN",
        pattern: "api.twilio.com",
        header: "Authorization",
        header_format: "Basic {secret}",
    },
    TrustedProxyDefinition {
        name: "cloudflare",
        secret_key: "CLOUDFLARE_API_TOKEN",
        pattern: "api.cloudflare.com",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "github_api",
        secret_key: "GITHUB_TOKEN",
        pattern: "api.github.com",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "pinecone",
        secret_key: "PINECONE_API_KEY",
        pattern: "pinecone.io",
        header: "Api-Key",
        header_format: "{secret}",
    },
    TrustedProxyDefinition {
        name: "replicate",
        secret_key: "REPLICATE_API_TOKEN",
        pattern: "api.replicate.com",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "xai",
        secret_key: "XAI_API_KEY",
        pattern: "api.x.ai",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "mistral",
        secret_key: "MISTRAL_API_KEY",
        pattern: "api.mistral.ai",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "perplexity",
        secret_key: "PERPLEXITY_API_KEY",
        pattern: "api.perplexity.ai",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "cohere",
        secret_key: "COHERE_API_KEY",
        pattern: "api.cohere.com",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "huggingface",
        secret_key: "HUGGINGFACE_API_KEY",
        pattern: "api-inference.huggingface.co",
        header: "Authorization",
        header_format: "Bearer {secret}",
    },
    TrustedProxyDefinition {
        name: "google_ai",
        secret_key: "GEMINI_API_KEY",
        pattern: "generativelanguage.googleapis.com",
        header: "x-goog-api-key",
        header_format: "{secret}",
    },
];

const DEFAULT_PROXY_SERVICE_NAMES: &[&str] = &[
    "openai",
    "anthropic",
    "stripe",
    "supabase",
    "xai",
    "mistral",
    "perplexity",
    "cohere",
    "replicate",
    "huggingface",
    "google_ai",
];

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
        let mut config: Self =
            toml::from_str(&content).map_err(|e| PhantomError::ConfigParseError(e.to_string()))?;
        validate_portable_project_id(&config.phantom.project_id)?;

        // `.phantom.toml` is repository-controlled. Its portable project_id is
        // retained for cloud/team identity, but it must never select
        // machine-local vault, shadow, or scheduler state. Derive that local
        // namespace exclusively from the canonical checkout directory.
        // Non-project TOML fixtures retain a compatibility fallback to the
        // serialized project ID.
        if path.file_name().and_then(|name| name.to_str()) == Some(".phantom.toml") {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let project_dir = std::fs::canonicalize(parent).map_err(PhantomError::Io)?;
            config.local_project_id = Some(Self::project_id_from_path(&project_dir));
        }

        Ok(config)
    }

    /// Save config to a file path.
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| PhantomError::ConfigParseError(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Return an exact trusted built-in proxy definition by service name.
    pub fn trusted_builtin_proxy_service(name: &str) -> Option<ServiceConfig> {
        TRUSTED_PROXY_SERVICES
            .iter()
            .find(|definition| definition.name == name)
            .copied()
            .map(TrustedProxyDefinition::service_config)
    }

    /// Return the trusted service name and exact proxy definition for an
    /// auto-detectable environment key.
    pub fn trusted_builtin_proxy_service_for_secret(
        secret_key: &str,
    ) -> Option<(&'static str, ServiceConfig)> {
        TRUSTED_PROXY_SERVICES
            .iter()
            .find(|definition| definition.secret_key == secret_key)
            .copied()
            .map(|definition| (definition.name, definition.service_config()))
    }

    /// Create a new config with default service patterns and a project ID.
    pub fn new_with_defaults(project_id: String) -> Self {
        let mut services: BTreeMap<String, ServiceConfig> = DEFAULT_PROXY_SERVICE_NAMES
            .iter()
            .map(|name| {
                let service = Self::trusted_builtin_proxy_service(name)
                    .expect("default proxy services must exist in the trusted registry");
                ((*name).to_string(), service)
            })
            .collect();

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

        Self {
            phantom: PhantomMeta {
                version: "1".to_string(),
                project_id: project_id.clone(),
                rotation_policy: None,
                secrets: BTreeMap::new(),
            },
            local_project_id: Some(project_id),
            services,
            sync: Vec::new(),
            cloud: None,
            public_keys: Vec::new(),
            alerting: AlertingConfig::default(),
        }
    }

    /// Return the effective `RotationSchedule` for `secret_name`.
    ///
    /// Resolution order:
    ///   1. Per-secret `rotation_schedule` in `[phantom.secrets.{name}]`
    ///   2. Per-secret `rotate_every` in `[phantom.secrets.{name}]`
    ///   3. Global `[phantom.rotation_policy]`
    ///   4. `None` — no schedule configured.
    pub fn get_rotation_schedule(&self, secret_name: &str) -> Option<RotationSchedule> {
        if let Some(ov) = self.phantom.secrets.get(secret_name) {
            if let Some(sched) = ov.resolve_schedule() {
                return Some(sched);
            }
        }
        self.phantom.rotation_policy.clone()
    }

    /// Generate a collision-resistant, machine-local project ID from a directory path.
    ///
    /// The platform tag and raw platform path encoding are domain-separated before
    /// hashing so distinct non-UTF-8 Unix paths cannot collapse through lossy string
    /// conversion. Local state is intentionally not portable across operating systems.
    pub fn project_id_from_path(path: &Path) -> String {
        // Resolve existing paths first so initialization and later config loads
        // agree even when the working directory traverses a platform symlink
        // (for example `/var` -> `/private/var` on macOS). For non-existing
        // fixture paths, retain the deterministic lexical fallback.
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

        let mut hasher = Sha256::new();
        hasher.update(b"phantom-local-project-v2\0");

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            hasher.update(b"unix\0");
            hasher.update(canonical.as_os_str().as_bytes());
        }

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            hasher.update(b"windows\0");
            for unit in canonical.as_os_str().encode_wide() {
                hasher.update(unit.to_le_bytes());
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            hasher.update(b"other\0");
            hasher.update(canonical.to_string_lossy().as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    /// Return the canonical-path-derived namespace for machine-local state.
    ///
    /// Configs deserialized directly from TOML (rather than loaded from a
    /// `.phantom.toml` path) fall back to the portable ID for compatibility
    /// with tests and embedding callers that have no checkout path.
    pub fn local_project_id(&self) -> &str {
        self.local_project_id
            .as_deref()
            .unwrap_or(&self.phantom.project_id)
    }

    /// Return the committed project identity used by cloud and team APIs.
    pub fn portable_project_id(&self) -> &str {
        &self.phantom.project_id
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

    /// Reject repository-authored proxy destinations that have not passed a
    /// machine-local trust decision. The v1 config format has no such approval
    /// ledger, so agentic proxy sessions are restricted to Phantom's exact
    /// built-in route definitions. Custom gateways can be added in a future
    /// format only with a value-blind, local approval record.
    pub fn validate_agentic_proxy_routes(&self) -> Result<()> {
        for (name, service) in &self.services {
            if let Some(expected) = Self::trusted_builtin_proxy_service(name) {
                if service != &expected {
                    return Err(PhantomError::ConfigParseError(format!(
                        "proxy service `{name}` differs from Phantom's trusted built-in route"
                    )));
                }
                continue;
            }

            if service.pattern.is_some() && service.secret_type == "api_key" {
                return Err(PhantomError::ConfigParseError(format!(
                    "custom proxy service `{name}` is not approved for agentic execution"
                )));
            }
        }
        Ok(())
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
    TRUSTED_PROXY_SERVICES
        .iter()
        .find(|definition| definition.name == name)
        .map(|definition| definition.pattern)
}

fn expected_pattern_for_secret(secret_key: &str) -> Option<&'static str> {
    TRUSTED_PROXY_SERVICES
        .iter()
        .find(|definition| definition.secret_key == secret_key)
        .map(|definition| definition.pattern)
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
        assert_eq!(config.portable_project_id(), "test123");
        assert_eq!(config.local_project_id(), "test123");
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
    fn project_config_preserves_portable_identity_across_clone_or_move() {
        let first = tempfile::TempDir::new().unwrap();
        let second = tempfile::TempDir::new().unwrap();
        let first_root = std::fs::canonicalize(first.path()).unwrap();
        let second_root = std::fs::canonicalize(second.path()).unwrap();
        let portable_id = PhantomConfig::project_id_from_path(&first_root);
        let config = PhantomConfig::new_with_defaults(portable_id.clone());
        let content = toml::to_string_pretty(&config).unwrap();
        let first_path = first.path().join(".phantom.toml");
        let second_path = second.path().join(".phantom.toml");
        std::fs::write(&first_path, &content).unwrap();
        std::fs::write(&second_path, &content).unwrap();

        let first_config = PhantomConfig::load(&first_path).unwrap();
        let second_config = PhantomConfig::load(&second_path).unwrap();

        assert_eq!(first_config.portable_project_id(), portable_id);
        assert_eq!(second_config.portable_project_id(), portable_id);
        assert_eq!(
            first_config.local_project_id(),
            PhantomConfig::project_id_from_path(&first_root)
        );
        assert_eq!(
            second_config.local_project_id(),
            PhantomConfig::project_id_from_path(&second_root)
        );
        assert_ne!(
            first_config.local_project_id(),
            second_config.local_project_id()
        );
    }

    #[test]
    fn saving_loaded_project_config_preserves_only_portable_identity() {
        let project = tempfile::TempDir::new().unwrap();
        let portable_id = "0123456789abcdef";
        let config = PhantomConfig::new_with_defaults(portable_id.to_string());
        let config_path = project.path().join(".phantom.toml");
        config.save(&config_path).unwrap();

        let loaded = PhantomConfig::load(&config_path).unwrap();
        assert_eq!(loaded.portable_project_id(), portable_id);
        assert_ne!(loaded.local_project_id(), portable_id);
        loaded.save(&config_path).unwrap();

        let saved = std::fs::read_to_string(&config_path).unwrap();
        assert!(saved.contains("project_id = \"0123456789abcdef\""));
        assert!(!saved.contains("local_project_id"));
        let reparsed: PhantomConfig = toml::from_str(&saved).unwrap();
        assert_eq!(reparsed.portable_project_id(), portable_id);
    }

    #[test]
    fn repository_project_id_cannot_select_another_local_namespace() {
        let victim = tempfile::TempDir::new().unwrap();
        let attacker = tempfile::TempDir::new().unwrap();
        let victim_root = std::fs::canonicalize(victim.path()).unwrap();
        let attacker_root = std::fs::canonicalize(attacker.path()).unwrap();
        let victim_local_id = PhantomConfig::project_id_from_path(&victim_root);
        let attacker_local_id = PhantomConfig::project_id_from_path(&attacker_root);
        let malicious_config = PhantomConfig::new_with_defaults(victim_local_id.clone());
        let config_path = attacker.path().join(".phantom.toml");
        malicious_config.save(&config_path).unwrap();

        let loaded = PhantomConfig::load(&config_path).unwrap();
        assert_eq!(loaded.portable_project_id(), victim_local_id);
        assert_eq!(loaded.local_project_id(), attacker_local_id);
        assert_ne!(loaded.local_project_id(), loaded.portable_project_id());
    }

    #[test]
    fn project_id_from_path_is_deterministic_collision_resistant_hex() {
        let project = tempfile::TempDir::new().unwrap();
        let first = PhantomConfig::project_id_from_path(project.path());
        let second = PhantomConfig::project_id_from_path(project.path());

        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn legacy_fnv_portable_id_cannot_select_the_local_namespace() {
        fn legacy_fnv_id(path: &Path) -> String {
            let canonical = std::fs::canonicalize(path).unwrap();
            let mut hash: u64 = 0xcbf29ce484222325;
            for byte in canonical.to_string_lossy().as_bytes() {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
            format!("{hash:016x}")
        }

        let project = tempfile::TempDir::new().unwrap();
        let legacy_id = legacy_fnv_id(project.path());
        let config_path = project.path().join(".phantom.toml");
        PhantomConfig::new_with_defaults(legacy_id.clone())
            .save(&config_path)
            .unwrap();

        let loaded = PhantomConfig::load(&config_path).unwrap();
        assert_eq!(loaded.portable_project_id(), legacy_id);
        assert_eq!(
            loaded.local_project_id(),
            PhantomConfig::project_id_from_path(project.path())
        );
        assert_ne!(loaded.local_project_id(), loaded.portable_project_id());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_do_not_collapse_through_lossy_conversion() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let parent = tempfile::TempDir::new().unwrap();
        let first = parent.path().join(OsString::from_vec(vec![b'p', 0xff]));
        let second = parent.path().join(OsString::from_vec(vec![b'p', 0xfe]));

        assert_ne!(
            PhantomConfig::project_id_from_path(&first),
            PhantomConfig::project_id_from_path(&second)
        );
    }

    #[test]
    fn project_config_rejects_path_and_url_component_project_ids() {
        let project = tempfile::TempDir::new().unwrap();
        let config_path = project.path().join(".phantom.toml");
        let invalid_ids = [
            "",
            ".",
            "..",
            "../victim",
            "..\\victim",
            "/absolute",
            "C:\\absolute",
            "nested/project",
            "project?admin=true",
            "project#fragment",
            "project%2Fvictim",
            "project name",
            "project\nname",
            "prójèct",
        ];

        for project_id in invalid_ids {
            let config = PhantomConfig::new_with_defaults(project_id.to_string());
            config.save(&config_path).unwrap();
            let error = PhantomConfig::load(&config_path).unwrap_err().to_string();
            assert!(
                error.contains("invalid portable project_id"),
                "unsafe project ID produced an unexpected error: {project_id:?}: {error}"
            );
        }

        let oversized = "a".repeat(129);
        let config = PhantomConfig::new_with_defaults(oversized);
        config.save(&config_path).unwrap();
        assert!(PhantomConfig::load(&config_path)
            .unwrap_err()
            .to_string()
            .contains("invalid portable project_id"));
    }

    #[test]
    fn project_config_accepts_portable_project_id_character_set() {
        let project = tempfile::TempDir::new().unwrap();
        let config_path = project.path().join(".phantom.toml");
        let portable_id = format!("A-z_9-{}", "x".repeat(122));
        assert_eq!(portable_id.len(), 128);
        PhantomConfig::new_with_defaults(portable_id.clone())
            .save(&config_path)
            .unwrap();

        let loaded = PhantomConfig::load(&config_path).unwrap();
        assert_eq!(loaded.portable_project_id(), portable_id);
    }

    #[test]
    fn agentic_proxy_routes_require_exact_built_in_definitions() {
        let mut config = PhantomConfig::new_with_defaults("test".to_string());
        assert!(config.validate_agentic_proxy_routes().is_ok());

        config.services.get_mut("openai").unwrap().pattern = Some("attacker.example".to_string());
        assert!(config.validate_agentic_proxy_routes().is_err());

        let mut custom = PhantomConfig::new_with_defaults("test".to_string());
        custom.services.insert(
            "custom".to_string(),
            ServiceConfig {
                secret_key: "CUSTOM_API_KEY".to_string(),
                pattern: Some("custom.example".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );
        assert!(custom.validate_agentic_proxy_routes().is_err());
    }

    #[test]
    fn trusted_proxy_registry_accepts_only_complete_canonical_definitions() {
        for definition in TRUSTED_PROXY_SERVICES {
            let exact = definition.service_config();
            let mut config = PhantomConfig::new_with_defaults("test".to_string());
            config.services.clear();
            config
                .services
                .insert(definition.name.to_string(), exact.clone());
            assert!(
                config.validate_agentic_proxy_routes().is_ok(),
                "canonical {} route should be trusted",
                definition.name
            );

            for altered in [
                ServiceConfig {
                    pattern: Some("attacker.example".to_string()),
                    ..exact.clone()
                },
                ServiceConfig {
                    secret_key: "DIFFERENT_SECRET".to_string(),
                    ..exact.clone()
                },
                ServiceConfig {
                    header: Some("X-Different".to_string()),
                    ..exact.clone()
                },
                ServiceConfig {
                    header_format: Some("{secret}-altered".to_string()),
                    ..exact.clone()
                },
                ServiceConfig {
                    secret_type: "connection_string".to_string(),
                    ..exact.clone()
                },
                ServiceConfig {
                    pattern: None,
                    ..exact.clone()
                },
            ] {
                config.services.insert(definition.name.to_string(), altered);
                assert!(
                    config.validate_agentic_proxy_routes().is_err(),
                    "altered {} route must fail closed",
                    definition.name
                );
            }
        }

        assert_eq!(
            PhantomConfig::trusted_builtin_proxy_service("replicate")
                .unwrap()
                .header_format
                .as_deref(),
            Some("Bearer {secret}")
        );
    }

    #[test]
    fn test_roundtrip_serialize() {
        let config = PhantomConfig::new_with_defaults("test".to_string());
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: PhantomConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.phantom.project_id, "test");
        assert_eq!(parsed.portable_project_id(), "test");
        assert_eq!(parsed.local_project_id(), "test");
        assert_eq!(parsed.services.len(), config.services.len());
    }

    #[test]
    fn test_project_id_from_path() {
        let id1 = PhantomConfig::project_id_from_path(Path::new("/home/user/project-a"));
        let id2 = PhantomConfig::project_id_from_path(Path::new("/home/user/project-b"));
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 64);
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

    // ── Rotation policy config tests ──────────────────────────────────────────

    #[test]
    fn rotation_policy_roundtrip_in_toml() {
        use crate::rotation_strategy::{RotationSchedule, RotationStrategy, Weekday};
        let mut config = PhantomConfig::new_with_defaults("rp_test".to_string());
        config.phantom.rotation_policy = Some(RotationSchedule {
            strategy: RotationStrategy::Daily,
            hour: 2,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: None,
        });
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(
            toml_str.contains("rotation_policy"),
            "TOML should contain rotation_policy"
        );
        let parsed: PhantomConfig = toml::from_str(&toml_str).unwrap();
        let rp = parsed.phantom.rotation_policy.unwrap();
        assert_eq!(rp.strategy, RotationStrategy::Daily);
        assert_eq!(rp.hour, 2);
    }

    #[test]
    fn get_rotation_schedule_falls_back_to_global() {
        use crate::rotation_strategy::{RotationSchedule, RotationStrategy, Weekday};
        let mut config = PhantomConfig::new_with_defaults("gs_test".to_string());
        config.phantom.rotation_policy = Some(RotationSchedule {
            strategy: RotationStrategy::Weekly,
            hour: 3,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: None,
        });
        // No per-secret override — should return global.
        let sched = config.get_rotation_schedule("OPENAI_API_KEY").unwrap();
        assert_eq!(sched.strategy, RotationStrategy::Weekly);
    }

    #[test]
    fn get_rotation_schedule_per_secret_overrides_global() {
        use crate::rotation_strategy::{RotationSchedule, RotationStrategy, Weekday};
        let mut config = PhantomConfig::new_with_defaults("ps_test".to_string());
        config.phantom.rotation_policy = Some(RotationSchedule {
            strategy: RotationStrategy::Monthly,
            hour: 0,
            minute: 0,
            weekday: Weekday::Monday,
            day_of_month: 1,
            last_rotated: None,
        });
        config.phantom.secrets.insert(
            "STRIPE_KEY".to_string(),
            SecretOverride {
                rotate_every: Some("7d".to_string()),
                rotation_schedule: None,
                audit: None,
                ..Default::default()
            },
        );
        let sched = config.get_rotation_schedule("STRIPE_KEY").unwrap();
        assert_eq!(sched.strategy, RotationStrategy::Weekly);
        // Other secrets still use global.
        let global = config.get_rotation_schedule("OTHER_KEY").unwrap();
        assert_eq!(global.strategy, RotationStrategy::Monthly);
    }

    #[test]
    fn parse_rotate_every_days() {
        assert!(parse_rotate_every("1d").is_some());
        assert!(parse_rotate_every("7d").is_some());
        assert!(parse_rotate_every("30d").is_some());
        assert!(parse_rotate_every("90d").is_some());
        assert!(parse_rotate_every("bad").is_none());
        assert!(parse_rotate_every("30").is_none());
    }

    #[test]
    fn per_secret_rotation_schedule_roundtrip() {
        use crate::rotation_strategy::{RotationSchedule, RotationStrategy, Weekday};
        let mut config = PhantomConfig::new_with_defaults("per_s".to_string());
        config.phantom.secrets.insert(
            "MY_KEY".to_string(),
            SecretOverride {
                rotate_every: None,
                rotation_schedule: Some(RotationSchedule {
                    strategy: RotationStrategy::Daily,
                    hour: 4,
                    minute: 30,
                    weekday: Weekday::Friday,
                    day_of_month: 15,
                    last_rotated: Some(1_000_000),
                }),
                audit: None,
                ..Default::default()
            },
        );
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: PhantomConfig = toml::from_str(&toml_str).unwrap();
        let ov = parsed.phantom.secrets.get("MY_KEY").unwrap();
        let sched = ov.resolve_schedule().unwrap();
        assert_eq!(sched.strategy, RotationStrategy::Daily);
        assert_eq!(sched.hour, 4);
        assert_eq!(sched.minute, 30);
        assert_eq!(sched.last_rotated, Some(1_000_000));
    }

    #[test]
    fn get_rotation_schedule_returns_none_when_unconfigured() {
        let config = PhantomConfig::new_with_defaults("none_test".to_string());
        assert!(config.get_rotation_schedule("OPENAI_API_KEY").is_none());
    }

    // ── ValidationScheduleConfig tests ───────────────────────────────────────

    #[test]
    fn validation_schedule_config_defaults() {
        let cfg = ValidationScheduleConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.schedule, "daily");
        assert_eq!(cfg.timeout_secs, 30);
    }

    #[test]
    fn validation_schedule_interval_daily() {
        let cfg = ValidationScheduleConfig {
            schedule: "daily".to_string(),
            ..Default::default()
        };
        assert_eq!(cfg.interval_secs(), Some(86_400));
    }

    #[test]
    fn validation_schedule_interval_weekly() {
        let cfg = ValidationScheduleConfig {
            schedule: "weekly".to_string(),
            ..Default::default()
        };
        assert_eq!(cfg.interval_secs(), Some(7 * 86_400));
    }

    #[test]
    fn validation_schedule_interval_never() {
        let cfg = ValidationScheduleConfig {
            schedule: "never".to_string(),
            ..Default::default()
        };
        assert_eq!(cfg.interval_secs(), None);
    }

    #[test]
    fn validation_schedule_disabled_not_due() {
        let cfg = ValidationScheduleConfig {
            enabled: false,
            schedule: "daily".to_string(),
            timeout_secs: 30,
            provider: None,
            alert_on_invalid: true,
        };
        // Disabled — never due, even if never checked.
        assert!(!cfg.is_due(0));
    }

    #[test]
    fn validation_schedule_never_checked_is_due() {
        let cfg = ValidationScheduleConfig::default();
        assert!(cfg.is_due(0));
    }

    #[test]
    fn validation_schedule_fresh_check_not_due() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cfg = ValidationScheduleConfig::default(); // daily
                                                       // Checked just now — not due.
        assert!(!cfg.is_due(now));
    }

    #[test]
    fn validation_schedule_old_check_is_due() {
        // last_check_ts = epoch+1 — more than a day ago.
        let cfg = ValidationScheduleConfig::default(); // daily
        assert!(cfg.is_due(1));
    }

    #[test]
    fn validation_schedule_never_never_due() {
        let cfg = ValidationScheduleConfig {
            enabled: true,
            schedule: "never".to_string(),
            timeout_secs: 30,
            provider: None,
            alert_on_invalid: true,
        };
        assert!(!cfg.is_due(0));
        assert!(!cfg.is_due(1));
    }

    #[test]
    fn validation_schedule_config_provider_and_alert_fields() {
        let cfg = ValidationScheduleConfig {
            enabled: true,
            schedule: "daily".to_string(),
            timeout_secs: 30,
            provider: Some("github".to_string()),
            alert_on_invalid: false,
        };
        assert_eq!(cfg.provider.as_deref(), Some("github"));
        assert!(!cfg.alert_on_invalid);

        // Round-trip through JSON.
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ValidationScheduleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider.as_deref(), Some("github"));
        assert!(!back.alert_on_invalid);
    }

    #[test]
    fn validation_schedule_config_defaults_alert_on_invalid_true() {
        let cfg = ValidationScheduleConfig::default();
        assert!(
            cfg.alert_on_invalid,
            "alert_on_invalid should default to true"
        );
        assert!(cfg.provider.is_none(), "provider should default to None");
    }

    #[test]
    fn validation_schedule_config_provider_none_omitted_from_toml() {
        let cfg = ValidationScheduleConfig::default();
        let toml_str = toml::to_string(&cfg).unwrap();
        // provider = None → skip_serializing_if → not present in TOML
        assert!(
            !toml_str.contains("provider"),
            "provider=None should be omitted: {toml_str}"
        );
    }

    #[test]
    fn secret_override_validation_field_roundtrip_toml() {
        let mut config = PhantomConfig::new_with_defaults("val_toml_test".to_string());
        config.phantom.secrets.insert(
            "STRIPE_KEY".to_string(),
            SecretOverride {
                validation: Some(ValidationScheduleConfig {
                    enabled: true,
                    schedule: "weekly".to_string(),
                    timeout_secs: 60,
                    provider: Some("stripe".to_string()),
                    alert_on_invalid: true,
                }),
                ..Default::default()
            },
        );

        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("weekly"), "TOML should contain 'weekly'");

        let parsed: PhantomConfig = toml::from_str(&toml_str).unwrap();
        let ov = parsed.phantom.secrets.get("STRIPE_KEY").unwrap();
        let val = ov.validation.as_ref().unwrap();
        assert_eq!(val.schedule, "weekly");
        assert_eq!(val.timeout_secs, 60);
        assert!(val.enabled);
        assert_eq!(val.provider.as_deref(), Some("stripe"));
        assert!(val.alert_on_invalid);
    }

    #[test]
    fn secret_override_no_validation_field_is_none_default() {
        let toml_str = r#"
[phantom]
version = "1"
project_id = "abc"

[phantom.secrets.MY_KEY]
rotate_every = "30d"
"#;
        let parsed: PhantomConfig = toml::from_str(toml_str).unwrap();
        let ov = parsed.phantom.secrets.get("MY_KEY").unwrap();
        // validation should be absent (None) when not specified
        assert!(ov.validation.is_none());
    }
}
