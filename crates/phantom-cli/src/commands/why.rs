use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{classify, is_public_key, DotenvFile, EnvEntry, SecretClassification};

/// Explain why a specific key is or isn't protected by Phantom.
pub fn run(key: &str) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let env_path = project_dir.join(".env");
    let config_path = project_dir.join(".phantom.toml");

    if !env_path.exists() {
        anyhow::bail!("No .env file found in current directory.");
    }

    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env")?;
    let config = PhantomConfig::load(&config_path).ok();

    // Find the entry
    let entry = dotenv.entries().into_iter().find(|e| e.key == key);

    match entry {
        Some(entry) => {
            if entry.is_phantom {
                // Already protected
                println!(
                    "{} {} is {}",
                    "->".blue().bold(),
                    key.bold(),
                    "PROTECTED".green().bold()
                );
                println!(
                    "   Token:  {}",
                    entry.value.get(..12).unwrap_or(&entry.value).dimmed()
                );

                // Show service mapping if available
                if let Some(ref cfg) = config {
                    for (svc_name, svc) in &cfg.services {
                        if svc.secret_key == key {
                            println!(
                                "   Service: {} ({})",
                                svc_name.cyan(),
                                svc.pattern.as_deref().unwrap_or("env var")
                            );
                            break;
                        }
                    }
                    println!(
                        "   Vault:  {}",
                        phantom_vault::create_vault(&cfg.phantom.project_id)
                            .backend_name()
                            .cyan()
                    );
                }
            } else {
                let classification = classify(entry);
                match classification {
                    SecretClassification::PublicKey => {
                        println!(
                            "{} {} is {} (public key)",
                            "->".blue().bold(),
                            key.bold(),
                            "NOT PROTECTED".yellow().bold()
                        );
                        let prefix = if key.starts_with("NEXT_PUBLIC_") {
                            "NEXT_PUBLIC_"
                        } else if key.starts_with("EXPO_PUBLIC_") {
                            "EXPO_PUBLIC_"
                        } else if key.starts_with("VITE_") {
                            "VITE_"
                        } else if key.starts_with("REACT_APP_") {
                            "REACT_APP_"
                        } else if key.starts_with("NUXT_PUBLIC_") {
                            "NUXT_PUBLIC_"
                        } else {
                            "GATSBY_"
                        };
                        println!(
                            "   Reason: Keys with {} prefix are browser-safe (shipped in client bundles)",
                            prefix.cyan()
                        );
                        println!(
                            "   Override: {}",
                            format!("phantom add --force {key}").dimmed()
                        );
                    }
                    SecretClassification::Secret => {
                        println!(
                            "{} {} is {} (detected as secret but not yet phantomized)",
                            "!".yellow().bold(),
                            key.bold(),
                            "UNPROTECTED".red().bold()
                        );
                        explain_why_secret(entry);
                        println!("   Fix: {}", "phantom init".cyan().bold());
                    }
                    SecretClassification::NotSecret => {
                        println!(
                            "{} {} is {} (non-secret config)",
                            "->".blue().bold(),
                            key.bold(),
                            "NOT PROTECTED".dimmed()
                        );
                        println!("   Reason: Does not match secret key patterns or value patterns");
                        println!(
                            "   Override: {}",
                            format!("phantom add {key} <value>").dimmed()
                        );
                    }
                }
            }
        }
        None => {
            // Key not in .env — check if it's a known public prefix
            if is_public_key(key) {
                println!(
                    "{} {} is not in .env, but would be classified as a {} (browser-safe)",
                    "->".blue().bold(),
                    key.bold(),
                    "public key".yellow()
                );
            } else {
                println!("{} {} not found in .env", "!".yellow().bold(), key.bold());
            }
        }
    }

    Ok(())
}

fn explain_why_secret(entry: &EnvEntry) {
    let key = entry.key.to_uppercase();
    let value = &entry.value;

    let secret_key_patterns = [
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "AUTH",
        "PRIVATE",
    ];
    let connection_patterns = ["DATABASE_URL", "REDIS_URL", "MONGO_URL"];

    for pattern in &secret_key_patterns {
        if key.contains(pattern) {
            println!(
                "   Reason: Key name contains \"{}\" (secret key pattern)",
                pattern
            );
            return;
        }
    }
    for pattern in &connection_patterns {
        if key.contains(pattern) {
            println!(
                "   Reason: Key name matches connection string pattern (\"{}\")",
                pattern
            );
            return;
        }
    }

    let secret_prefixes = [
        ("sk-", "OpenAI-style key"),
        ("sk_", "Stripe-style key"),
        ("ghp_", "GitHub token"),
        ("eyJ", "JWT/base64 token"),
    ];
    for (prefix, label) in &secret_prefixes {
        if value.starts_with(prefix) {
            println!("   Reason: Value starts with \"{}\" ({})", prefix, label);
            return;
        }
    }

    if value.contains("://") && value.contains('@') {
        println!("   Reason: Value looks like a connection string with credentials");
        return;
    }

    if value.len() >= 32 {
        println!(
            "   Reason: Value is a high-entropy string ({} chars)",
            value.len()
        );
    }
}
