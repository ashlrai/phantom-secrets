use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::{PhantomConfig, ServiceConfig};
use phantom_core::dotenv::{DotenvFile, EnvEntry};
use phantom_core::token::TokenMap;
use std::collections::BTreeMap;
use std::path::Path;

pub fn run(env_path_arg: &str) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    // Auto-detect .env file if the default wasn't found
    let env_path = if Path::new(env_path_arg).exists() {
        std::path::PathBuf::from(env_path_arg)
    } else {
        find_env_file(&project_dir, env_path_arg).ok_or_else(|| {
            anyhow::anyhow!(
                "No .env file found.\n\
                 Checked: .env, .env.local, .env.development, .env.development.local\n\n\
                 Create a .env file with your secrets, or specify one:\n\
                 {}",
                "phantom init --from .env.local".cyan().bold()
            )
        })?
    };

    // Parse .env file
    println!("{} Reading {}...", "->".blue().bold(), env_path.display());
    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env file")?;

    let real_entries = dotenv.real_secret_entries();
    if real_entries.is_empty() {
        println!(
            "{} No real secrets found in {} (all values are already phantom tokens or empty)",
            "!".yellow().bold(),
            env_path.display()
        );
        return Ok(());
    }

    println!(
        "{} Found {} secret(s) to protect:",
        "->".blue().bold(),
        real_entries.len()
    );
    for entry in &real_entries {
        println!("   {} {}", "-".dimmed(), entry.key.bold());
    }

    // Generate project ID and config
    let project_id = PhantomConfig::project_id_from_path(&project_dir);
    let mut config = if config_path.exists() {
        println!("{} Loading existing .phantom.toml", "->".blue().bold());
        PhantomConfig::load(&config_path)?
    } else {
        PhantomConfig::new_with_defaults(project_id.clone())
    };

    // Auto-detect services from key names
    let detected = auto_detect_services(&real_entries, &config);
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

    // Create vault
    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    println!(
        "{} Using {} vault backend",
        "->".blue().bold(),
        vault.backend_name().cyan()
    );

    // Generate phantom tokens and store real secrets
    let mut token_map = TokenMap::new();
    for entry in &real_entries {
        let token = token_map.insert(entry.key.clone());
        vault
            .store(&entry.key, &entry.value)
            .context(format!("Failed to store secret: {}", entry.key))?;
        println!(
            "   {} {} -> {}",
            "+".green().bold(),
            entry.key.bold(),
            token.as_str()[..12].dimmed()
        );
    }

    // Backup .env before rewriting (safety net against data loss)
    let backup_path = env_path.with_file_name(".env.backup");
    std::fs::copy(&env_path, &backup_path).context("Failed to create .env backup")?;
    println!(
        "   {} Backed up original .env to {}",
        "+".green().bold(),
        backup_path.display()
    );

    // Rewrite .env with phantom tokens
    let _originals = dotenv
        .write_phantomized(&token_map, &env_path)
        .context("Failed to rewrite .env file")?;

    println!(
        "\n{} Rewrote {} with phantom tokens",
        "ok".green().bold(),
        env_path.display()
    );

    // Save config
    config.save(&config_path)?;
    println!("{} Saved .phantom.toml", "ok".green().bold());

    // Add .phantom.toml to .gitignore if needed
    ensure_gitignore(&project_dir)?;

    println!(
        "\n{} {} secret(s) are now protected!",
        "done".green().bold(),
        real_entries.len()
    );

    // Auto-configure Claude Code if detected (merges phantom setup into init)
    auto_setup_claude_code(&project_dir);

    // Add Phantom instructions to CLAUDE.md so Claude knows how to use it
    auto_add_claude_md(&project_dir);

    println!(
        "\n{} Run {} to start coding with AI safely.",
        "next".blue().bold(),
        "phantom exec -- <your-command>".cyan().bold()
    );

    Ok(())
}

/// Auto-detect .env files in common locations.
fn find_env_file(project_dir: &Path, user_specified: &str) -> Option<std::path::PathBuf> {
    let candidates = [
        user_specified,
        ".env.local",
        ".env",
        ".env.development",
        ".env.development.local",
    ];
    for candidate in &candidates {
        let path = project_dir.join(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn ensure_gitignore(project_dir: &Path) -> Result<()> {
    let gitignore_path = project_dir.join(".gitignore");

    let mut content = if gitignore_path.exists() {
        std::fs::read_to_string(&gitignore_path)?
    } else {
        String::new()
    };

    let mut added = Vec::new();

    // Ensure .phantom.toml is NOT ignored (it contains no secrets, and teammates need it)
    // But ensure .env is ignored
    for pattern in &[".env", ".env.local", ".env.*.local", ".env.backup"] {
        if !content.lines().any(|l| l.trim() == *pattern) {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(pattern);
            content.push('\n');
            added.push(*pattern);
        }
    }

    if !added.is_empty() {
        std::fs::write(&gitignore_path, &content)?;
        println!(
            "{} Added {} to .gitignore",
            "ok".green().bold(),
            added.join(", ")
        );
    }

    Ok(())
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

/// Auto-configure Claude Code MCP server and .env permissions if Claude Code is detected.
fn auto_setup_claude_code(project_dir: &Path) {
    let claude_dir = project_dir.join(".claude");
    let settings_path = claude_dir.join("settings.local.json");

    // Only auto-configure if .claude directory already exists (user has Claude Code)
    if !claude_dir.exists() {
        return;
    }

    let mut settings: serde_json::Value = if settings_path.exists() {
        match std::fs::read_to_string(&settings_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or(serde_json::json!({})),
            Err(_) => return,
        }
    } else {
        serde_json::json!({})
    };

    let obj = match settings.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    let mut changed = false;

    // Add MCP server (use npx for portability)
    let mcp_servers = obj
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(servers) = mcp_servers.as_object_mut() {
        if !servers.contains_key("phantom") {
            servers.insert(
                "phantom".to_string(),
                serde_json::json!({
                    "command": "npx",
                    "args": ["phantom-secrets-mcp"]
                }),
            );
            println!("{} Configured Claude Code MCP server", "ok".green().bold());
            changed = true;
        }
    }

    // Add .env read permissions
    let permissions = obj
        .entry("permissions")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(perms) = permissions.as_object_mut() {
        let allow = perms
            .entry("allow")
            .or_insert_with(|| serde_json::json!([]));
        if let Some(allow_arr) = allow.as_array_mut() {
            for rule in &["Read(./.env)", "Read(./.env.*)"] {
                if !allow_arr.iter().any(|v| v.as_str() == Some(rule)) {
                    allow_arr.push(serde_json::json!(rule));
                    changed = true;
                }
            }
            if changed {
                println!(
                    "{} Allowed Claude Code to read .env (phantom tokens only)",
                    "ok".green().bold()
                );
            }
        }
    }

    if changed {
        if let Ok(content) = serde_json::to_string_pretty(&settings) {
            let _ = std::fs::write(&settings_path, content);
        }
    }
}

/// Add Phantom usage instructions to the project's CLAUDE.md so Claude knows how to use it.
fn auto_add_claude_md(project_dir: &Path) {
    let claude_md = project_dir.join("CLAUDE.md");
    let phantom_marker = "## Phantom Secrets";

    let mut content = if claude_md.exists() {
        match std::fs::read_to_string(&claude_md) {
            Ok(c) => c,
            Err(_) => return,
        }
    } else {
        String::new()
    };

    // Don't add if already present
    if content.contains(phantom_marker) {
        return;
    }

    let instructions = r#"
## Phantom Secrets

This project uses [Phantom](https://phm.dev) to protect API keys from AI leaks.

- The `.env` file contains **phantom tokens** (`phm_...`), not real secrets
- Real secrets are in an encrypted vault (OS keychain)
- Use the Phantom MCP tools to manage secrets — never ask the user for raw API key values
- To add a secret: use the `phantom_add_secret` MCP tool
- To list secrets: use the `phantom_list_secrets` MCP tool
- The proxy (`phantom exec`) injects real credentials at the network layer
"#;

    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(instructions);

    match std::fs::write(&claude_md, &content) {
        Ok(_) => println!(
            "{} Added Phantom instructions to CLAUDE.md",
            "ok".green().bold()
        ),
        Err(e) => println!(
            "{} Could not update CLAUDE.md: {}",
            "warn".yellow().bold(),
            e
        ),
    }
}
