use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::sync::{self, Platform};
use phantom_core::token::TokenMap;

pub fn run(
    from: &str,
    project: &str,
    environment: Option<String>,
    service: Option<String>,
    force: bool,
) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(from, project, environment, service, force))
}

async fn run_async(
    from: &str,
    project: &str,
    environment: Option<String>,
    service: Option<String>,
    force: bool,
) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let env_path = project_dir.join(".env");

    let platform: Platform = from.parse().context("Invalid platform")?;

    // Determine API token
    let token_env = match platform {
        Platform::Vercel => "VERCEL_TOKEN",
        Platform::Railway => "RAILWAY_TOKEN",
    };
    let token = std::env::var(token_env).context(format!(
        "{token_env} not set. Export your {platform} API token."
    ))?;

    println!(
        "{} Pulling secrets from {} (project: {})...",
        "->".blue().bold(),
        platform.to_string().cyan().bold(),
        project.dimmed()
    );

    // Pull secrets from platform
    let pulled = match platform {
        Platform::Vercel => sync::pull_from_vercel(&token, project)
            .await
            .map_err(|e| anyhow::anyhow!("Vercel pull failed: {e}"))?,
        Platform::Railway => {
            let env_id = environment.as_deref().unwrap_or("production");
            sync::pull_from_railway(&token, project, env_id, service.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!("Railway pull failed: {e}"))?
        }
    };

    if pulled.is_empty() {
        println!("{} No secrets found on {}.", "!".yellow().bold(), platform);
        return Ok(());
    }

    println!(
        "{} Found {} secret(s) on {}",
        "ok".green().bold(),
        pulled.len(),
        platform
    );

    // Load or create config
    let project_id = PhantomConfig::project_id_from_path(&project_dir);
    let config = if config_path.exists() {
        PhantomConfig::load(&config_path)?
    } else {
        PhantomConfig::new_with_defaults(project_id.clone())
    };

    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    let existing_names = vault.list().unwrap_or_default();

    let mut token_map = TokenMap::new();
    let mut new_count = 0;
    let mut updated_count = 0;
    let mut skipped_count = 0;

    for (key, value) in &pulled {
        let exists = existing_names.contains(key);

        if exists && !force {
            println!(
                "   {} {} (exists, use --force to overwrite)",
                "-".dimmed(),
                key
            );
            skipped_count += 1;
            continue;
        }

        // Store in vault
        vault
            .store(key, value)
            .context(format!("Failed to store {key}"))?;

        // Generate phantom token for .env
        token_map.insert(key.clone());

        if exists {
            println!("   {} {} (overwritten)", "~".blue(), key.bold());
            updated_count += 1;
        } else {
            println!("   {} {} (new)", "+".green().bold(), key.bold());
            new_count += 1;
        }
    }

    // Update .env file with phantom tokens for new/updated secrets
    if new_count > 0 || updated_count > 0 {
        let mut env_content = if env_path.exists() {
            std::fs::read_to_string(&env_path)?
        } else {
            String::new()
        };

        for key in pulled.keys() {
            if let Some(token) = token_map.get_token(key) {
                // Check if key already exists in .env
                let key_prefix = format!("{key}=");
                if env_content.lines().any(|l| l.starts_with(&key_prefix)) {
                    // Update existing line
                    env_content = env_content
                        .lines()
                        .map(|line| {
                            if line.starts_with(&key_prefix) {
                                format!("{key}={token}")
                            } else {
                                line.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                } else {
                    // Append new entry
                    if !env_content.is_empty() && !env_content.ends_with('\n') {
                        env_content.push('\n');
                    }
                    env_content.push_str(&format!("{key}={token}\n"));
                }
            }
        }

        std::fs::write(&env_path, &env_content)?;
    }

    // Save config
    config.save(&config_path)?;

    println!();
    println!(
        "{} Pull complete: {} new, {} updated, {} skipped",
        "ok".green().bold(),
        new_count,
        updated_count,
        skipped_count
    );

    if new_count > 0 || updated_count > 0 {
        println!(
            "{} .env updated with phantom tokens. Real values in vault.",
            "ok".green().bold()
        );
    }

    Ok(())
}
