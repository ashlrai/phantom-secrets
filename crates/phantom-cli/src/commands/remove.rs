use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::{namespaced_key, DEFAULT_ENV};

pub fn run(name: &str, env: Option<&str>) -> Result<()> {
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

    let active_env = crate::commands::env_scope::effective_env(&project_dir, env);
    let vault_key = namespaced_key(&active_env, name);

    // Try namespaced key first; for default env fall back to bare name for
    // backward compatibility with pre-env-scoping vaults.
    let result = vault.delete(&vault_key);
    let result =
        if result.is_err() && active_env == DEFAULT_ENV && vault.exists(name).unwrap_or(false) {
            vault.delete(name)
        } else {
            result
        };

    result.context(format!("Failed to remove secret: {name}"))?;

    println!(
        "{} Removed {} from vault [env: {}]",
        "ok".green().bold(),
        name.bold(),
        active_env.cyan()
    );

    Ok(())
}
