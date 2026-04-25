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

    // Map of key name patterns to service configs
    let known_services: Vec<(&str, &str, &str, &str, &str, &str)> = vec![
        // (key_name, service_name, pattern, header, header_format, type)
        (
            "OPENAI_API_KEY",
            "openai",
            "api.openai.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "ANTHROPIC_API_KEY",
            "anthropic",
            "api.anthropic.com",
            "x-api-key",
            "{secret}",
            "api_key",
        ),
        (
            "STRIPE_SECRET_KEY",
            "stripe",
            "api.stripe.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "STRIPE_PUBLISHABLE_KEY",
            "stripe_pub",
            "api.stripe.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "SUPABASE_SERVICE_ROLE_KEY",
            "supabase",
            "supabase.co",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "SUPABASE_ANON_KEY",
            "supabase_anon",
            "supabase.co",
            "apikey",
            "{secret}",
            "api_key",
        ),
        (
            "RESEND_API_KEY",
            "resend",
            "api.resend.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "SENDGRID_API_KEY",
            "sendgrid",
            "api.sendgrid.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "TWILIO_AUTH_TOKEN",
            "twilio",
            "api.twilio.com",
            "Authorization",
            "Basic {secret}",
            "api_key",
        ),
        (
            "CLOUDFLARE_API_TOKEN",
            "cloudflare",
            "api.cloudflare.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "GITHUB_TOKEN",
            "github_api",
            "api.github.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "PINECONE_API_KEY",
            "pinecone",
            "pinecone.io",
            "Api-Key",
            "{secret}",
            "api_key",
        ),
        (
            "REPLICATE_API_TOKEN",
            "replicate",
            "api.replicate.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
    ];

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
        // Check known API services
        for (key_name, svc_name, pattern, header, header_format, svc_type) in &known_services {
            if entry.key == *key_name && !existing_config.services.contains_key(*svc_name) {
                detected.insert(
                    svc_name.to_string(),
                    ServiceConfig {
                        secret_key: key_name.to_string(),
                        pattern: Some(pattern.to_string()),
                        header: Some(header.to_string()),
                        header_format: Some(header_format.to_string()),
                        secret_type: svc_type.to_string(),
                    },
                );
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
