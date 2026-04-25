use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::sync::{self, Platform, SyncStatus};
use std::collections::BTreeMap;
use zeroize::Zeroize;

pub fn run(platform: Option<String>, project: Option<String>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(platform, project))
}

async fn run_async(
    platform_filter: Option<String>,
    project_override: Option<String>,
) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    // Get all real secret values from vault
    let secret_names = vault.list().context("Failed to list secrets")?;
    let mut secrets: BTreeMap<String, String> = BTreeMap::new();
    for name in &secret_names {
        match vault.retrieve(name) {
            Ok(value) => {
                secrets.insert(name.clone(), String::from(value.as_str()));
            }
            Err(_) => {
                eprintln!(
                    "{} Could not retrieve {} from vault, skipping",
                    "warn".yellow(),
                    name
                );
            }
        }
    }

    if secrets.is_empty() {
        println!("{} No secrets in vault to sync.", "!".yellow().bold());
        return Ok(());
    }

    // Determine sync targets
    let targets: Vec<_> = if config.sync.is_empty() {
        // No sync targets configured — try to infer from platform arg
        if let Some(platform_str) = &platform_filter {
            let platform: Platform = platform_str.parse().context("Invalid platform")?;

            let token_env = match platform {
                Platform::Vercel => "VERCEL_TOKEN",
                Platform::Railway => "RAILWAY_TOKEN",
            };

            let token = std::env::var(token_env).context(format!(
                "{token_env} not set. Export your {} API token.",
                platform
            ))?;

            let project_id = project_override.clone().context(
                "No project ID specified. Use --project <id> or add [[sync]] to .phantom.toml",
            )?;

            vec![(
                platform,
                token,
                project_id,
                vec!["production".to_string(), "preview".to_string()],
                None,
                None,
            )]
        } else {
            eprintln!("{} No sync targets configured.", "!".yellow().bold());
            eprintln!();
            eprintln!("Add sync targets to .phantom.toml:");
            eprintln!();
            eprintln!("  {}", r#"[[sync]]"#.dimmed());
            eprintln!("  {}", r#"platform = "vercel""#.dimmed());
            eprintln!("  {}", r#"token_env = "VERCEL_TOKEN""#.dimmed());
            eprintln!("  {}", r#"project_id = "prj_your_project_id""#.dimmed());
            eprintln!();
            eprintln!(
                "Or run: {} {} {}",
                "phantom sync".cyan().bold(),
                "--platform vercel".cyan(),
                "--project <project-id>".cyan()
            );
            return Ok(());
        }
    } else {
        // Use configured sync targets
        config
            .sync
            .iter()
            .filter(|t| {
                if let Some(filter) = &platform_filter {
                    t.platform.to_string() == *filter
                } else {
                    true
                }
            })
            .map(|t| {
                let token = std::env::var(&t.token_env).unwrap_or_default();
                let pid = project_override
                    .clone()
                    .unwrap_or_else(|| t.project_id.clone());
                (
                    t.platform.clone(),
                    token,
                    pid,
                    t.targets.clone(),
                    t.service_id.clone(),
                    t.environment_id.clone(),
                )
            })
            .collect()
    };

    if targets.is_empty() {
        println!("{} No matching sync targets.", "!".yellow().bold());
        return Ok(());
    }

    for (platform, token, project_id, env_targets, service_id, environment_id) in &targets {
        if token.is_empty() {
            let token_env = match platform {
                Platform::Vercel => "VERCEL_TOKEN",
                Platform::Railway => "RAILWAY_TOKEN",
            };
            eprintln!(
                "{} {} not set — skipping {}",
                "warn".yellow(),
                token_env,
                platform
            );
            continue;
        }

        println!(
            "\n{} Syncing {} secret(s) to {} (project: {})...",
            "->".blue().bold(),
            secrets.len(),
            platform.to_string().cyan().bold(),
            project_id.dimmed()
        );

        let results = match platform {
            Platform::Vercel => {
                sync::sync_to_vercel(token, project_id, &secrets, env_targets).await
            }
            Platform::Railway => {
                let env_id = environment_id.as_deref().unwrap_or("production");
                sync::sync_to_railway(token, project_id, env_id, service_id.as_deref(), &secrets)
                    .await
            }
        };

        let mut created = 0;
        let mut updated = 0;
        let mut errors = 0;

        for result in &results {
            match &result.status {
                SyncStatus::Created => {
                    println!("   {} {} (created)", "+".green(), result.key.bold());
                    created += 1;
                }
                SyncStatus::Updated => {
                    println!("   {} {} (updated)", "~".blue(), result.key.bold());
                    updated += 1;
                }
                SyncStatus::Unchanged => {
                    println!("   {} {} (unchanged)", "-".dimmed(), result.key);
                }
                SyncStatus::Error(e) => {
                    eprintln!("   {} {} ({})", "!".red().bold(), result.key.bold(), e);
                    errors += 1;
                }
            }
        }

        println!();
        if errors > 0 {
            println!(
                "{} {}: {} created, {} updated, {} errors",
                "!".yellow().bold(),
                platform,
                created,
                updated,
                errors
            );
        } else {
            println!(
                "{} {}: {} created, {} updated",
                "ok".green().bold(),
                platform,
                created,
                updated
            );
        }
    }

    for value in secrets.values_mut() {
        value.zeroize();
    }
    drop(secrets);

    Ok(())
}
