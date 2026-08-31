use colored::Colorize;
use phantom_core::config::{PhantomConfig, ServiceConfig};
use phantom_core::dotenv::EnvEntry;
use std::collections::BTreeMap;
use std::path::Path;

/// Load or create a PhantomConfig and auto-detect services from .env key names.
pub fn load_or_create(project_dir: &Path, config_path: &Path) -> anyhow::Result<PhantomConfig> {
    let project_id = PhantomConfig::project_id_from_path(project_dir);
    let config = if config_path.exists() {
        println!("{} Loading existing .phantom.toml", "->".blue().bold());
        PhantomConfig::load(config_path)?
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
            if entry.key == *conn_key
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
}
