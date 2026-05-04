use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::env_scope::{split_key, DEFAULT_ENV};
use phantom_core::token::TokenMap;

pub fn run(sync_after: bool, env: Option<&str>) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let env_path = project_dir.join(".env");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    let all_keys = vault.list().context("Failed to list secrets")?;

    let active_env = crate::commands::env_scope::effective_env(&project_dir, env);

    // Only rotate secrets belonging to the active environment.
    let env_keys: Vec<(String, String)> = all_keys
        .iter()
        .filter_map(|k| {
            if let Some((e, name)) = split_key(k) {
                if e == active_env {
                    return Some((k.clone(), name.to_string()));
                }
            } else if active_env == DEFAULT_ENV {
                return Some((k.clone(), k.clone()));
            }
            None
        })
        .collect();

    if env_keys.is_empty() {
        println!(
            "{} No secrets to rotate in env '{}'.",
            "!".yellow().bold(),
            active_env
        );
        return Ok(());
    }

    let mut token_map = TokenMap::new();
    for (_, name) in &env_keys {
        token_map.insert(name.clone());
    }

    if env_path.exists() {
        let dotenv = DotenvFile::parse_file(&env_path)?;
        dotenv.write_phantomized(&token_map, &env_path)?;
        println!(
            "{} Rotated {} phantom token(s) in .env [env: {}]",
            "ok".green().bold(),
            env_keys.len(),
            active_env.cyan()
        );
    } else {
        println!(
            "{} No .env file found — tokens rotated in memory only",
            "!".yellow().bold()
        );
    }

    for (_, name) in &env_keys {
        println!("   {} {} -> new token", "+".green(), name.bold());
    }

    // TODO(env-v2): pass active_env to sync for per-env sync targets
    if sync_after {
        println!(
            "\n{} Syncing to deployment platforms...",
            "->".blue().bold()
        );
        crate::commands::sync::run(None, None, vec![], None)?;
    }

    Ok(())
}
