use colored::Colorize;
use phantom_core::config::{PhantomConfig, ServiceConfig};
use phantom_core::dotenv::EnvEntry;
use std::collections::BTreeMap;
use std::path::Path;

/// Load or create a PhantomConfig from an exact, safely-read before-image.
/// Existing config is rechecked after parsing so a concurrent editor cannot
/// silently change project identity between preflight and transaction setup.
pub fn load_or_create(
    project_dir: &Path,
    config_path: &Path,
    config_before: Option<&[u8]>,
) -> anyhow::Result<PhantomConfig> {
    let project_id = PhantomConfig::project_id_from_path(project_dir);
    let config = if config_before.is_some() {
        println!("{} Loading existing .phantom.toml", "->".blue().bold());
        let config = PhantomConfig::load(config_path)?;
        let after = phantom_core::fs::read_regular_file(config_path)?;
        if after.as_deref() != config_before {
            anyhow::bail!(".phantom.toml changed while init was reading it; no changes were made");
        }
        config
    } else {
        PhantomConfig::new_with_defaults(project_id)
    };
    Ok(config)
}

/// Merge auto-detected services into config, printing what was found.
pub fn apply_detected_services(config: &mut PhantomConfig, real_entries: &[&EnvEntry]) {
    let detected = auto_detect_services(real_entries, config);
    for (name, svc) in detected {
        if let std::collections::btree_map::Entry::Vacant(entry) =
            config.services.entry(name.clone())
        {
            println!(
                "   {} Auto-detected service: {} ({})",
                "+".cyan().bold(),
                name.bold(),
                svc.pattern.as_deref().unwrap_or("env var")
            );
            entry.insert(svc);
        }
    }
}

/// Protected keys that `phantom exec` and `phantom start` will refuse to
/// launch with, because connection strings are not proxied yet.
pub fn protected_connection_string_keys(
    config: &PhantomConfig,
    real_entries: &[&EnvEntry],
) -> Vec<String> {
    let blocked: std::collections::BTreeSet<&str> = config
        .connection_string_services()
        .into_iter()
        .map(|(_, service)| service.secret_key.as_str())
        .collect();
    let mut keys: Vec<String> = real_entries
        .iter()
        .filter(|entry| blocked.contains(entry.key.as_str()))
        .map(|entry| entry.key.clone())
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Auto-detect service configurations from .env key names.
fn auto_detect_services(
    entries: &[&EnvEntry],
    existing_config: &PhantomConfig,
) -> BTreeMap<String, ServiceConfig> {
    let mut detected = BTreeMap::new();

    // Connection string patterns
    let conn_string_keys = [
        "DATABASE_URL",
        "REDIS_URL",
        "MONGO_URL",
        "MONGODB_URI",
        "POSTGRES_URL",
        "MYSQL_URL",
        "AMQP_URL",
        "ELASTICSEARCH_URL",
    ];

    for entry in entries {
        // Resolve API services through the same exact registry used by
        // agentic route validation. Init can therefore never emit a built-in
        // definition that validation later rejects.
        if let Some((service_name, service)) =
            PhantomConfig::trusted_builtin_proxy_service_for_secret(&entry.key)
        {
            if !existing_config.services.contains_key(service_name) {
                detected.insert(service_name.to_string(), service);
            }
        }

        // Check connection strings
        for conn_key in &conn_string_keys {
            // Built-in defaults already map some keys (for example the
            // `database` service owns DATABASE_URL). Adding a second service
            // for the same key only duplicated it in config and diagnostics.
            let already_mapped = existing_config
                .services
                .values()
                .chain(detected.values())
                .any(|service| service.secret_key == entry.key);
            if entry.key == *conn_key
                && !already_mapped
                && !existing_config
                    .services
                    .contains_key(&entry.key.to_lowercase())
            {
                detected.insert(
                    entry.key.to_lowercase(),
                    ServiceConfig {
                        secret_key: entry.key.clone(),
                        pattern: None,
                        header: None,
                        header_format: None,
                        secret_type: "connection_string".to_string(),
                    },
                );
            }
        }
    }

    detected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_auto_detected_proxy_route_passes_exact_agentic_validation() {
        let expected = [
            ("OPENAI_API_KEY", "openai"),
            ("ANTHROPIC_API_KEY", "anthropic"),
            ("STRIPE_SECRET_KEY", "stripe"),
            ("STRIPE_PUBLISHABLE_KEY", "stripe_pub"),
            ("SUPABASE_SERVICE_ROLE_KEY", "supabase"),
            ("SUPABASE_ANON_KEY", "supabase_anon"),
            ("RESEND_API_KEY", "resend"),
            ("SENDGRID_API_KEY", "sendgrid"),
            ("TWILIO_AUTH_TOKEN", "twilio"),
            ("CLOUDFLARE_API_TOKEN", "cloudflare"),
            ("GITHUB_TOKEN", "github_api"),
            ("PINECONE_API_KEY", "pinecone"),
            ("REPLICATE_API_TOKEN", "replicate"),
            ("XAI_API_KEY", "xai"),
            ("MISTRAL_API_KEY", "mistral"),
            ("PERPLEXITY_API_KEY", "perplexity"),
            ("COHERE_API_KEY", "cohere"),
            ("HUGGINGFACE_API_KEY", "huggingface"),
            ("GEMINI_API_KEY", "google_ai"),
        ];
        let entries: Vec<EnvEntry> = expected
            .iter()
            .map(|(key, _)| EnvEntry {
                key: (*key).to_string(),
                value: "test-value".to_string(),
                is_phantom: false,
            })
            .collect();
        let entry_refs: Vec<&EnvEntry> = entries.iter().collect();
        let mut config = PhantomConfig::new_with_defaults("test".to_string());
        config.services.clear();

        let detected = auto_detect_services(&entry_refs, &config);
        config.services.extend(detected);

        assert_eq!(config.services.len(), expected.len());
        for (_, service_name) in expected {
            assert!(
                config.services.contains_key(service_name),
                "missing auto-detected service {service_name}"
            );
        }
        config
            .validate_agentic_proxy_routes()
            .expect("init-generated routes must be exact trusted built-ins");

        config.services.get_mut("resend").unwrap().pattern = Some("attacker.example".to_string());
        assert!(config.validate_agentic_proxy_routes().is_err());
    }

    fn entry(key: &str) -> EnvEntry {
        EnvEntry {
            key: key.to_string(),
            value: "test-value".to_string(),
            is_phantom: false,
        }
    }

    #[test]
    fn default_database_service_is_not_duplicated_by_auto_detection() {
        let entries = [entry("DATABASE_URL"), entry("REDIS_URL")];
        let refs: Vec<&EnvEntry> = entries.iter().collect();
        let mut config = PhantomConfig::new_with_defaults("test".to_string());
        apply_detected_services(&mut config, &refs);

        let database_url_services: Vec<&str> = config
            .connection_string_services()
            .into_iter()
            .filter(|(_, service)| service.secret_key == "DATABASE_URL")
            .map(|(name, _)| name)
            .collect();
        assert_eq!(database_url_services, vec!["database"]);
        assert!(!config.services.contains_key("database_url"));
        // Keys without a default mapping are still detected.
        assert_eq!(
            config
                .services
                .get("redis_url")
                .map(|s| s.secret_key.as_str()),
            Some("REDIS_URL")
        );
    }

    #[test]
    fn protected_connection_string_keys_are_sorted_and_unique() {
        let entries = [
            entry("OPENAI_API_KEY"),
            entry("REDIS_URL"),
            entry("DATABASE_URL"),
        ];
        let refs: Vec<&EnvEntry> = entries.iter().collect();
        let mut config = PhantomConfig::new_with_defaults("test".to_string());
        apply_detected_services(&mut config, &refs);
        // A config written by an older init can still carry a duplicate.
        config.services.insert(
            "database_url".to_string(),
            config.services["database"].clone(),
        );

        assert_eq!(
            protected_connection_string_keys(&config, &refs),
            vec!["DATABASE_URL".to_string(), "REDIS_URL".to_string()]
        );
    }
}
