#![allow(dead_code)]
/// `phantom env` subcommands for environment scoping.
///
/// This module handles `use`, `list`, `new`, and `copy` — the environment
/// selector commands. The legacy `phantom env` (generate .env.example) is
/// still available as `phantom env example` (see `commands/env.rs`).
use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::{
    known_envs_from_keys, namespaced_key, resolve_env, split_key, validate_env_name,
    write_active_env, DEFAULT_ENV,
};

/// `phantom env use <name>` — set the active environment.
pub fn run_use(name: &str) -> Result<()> {
    validate_env_name(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let project_dir = std::env::current_dir()?;
    write_active_env(&project_dir, name).context("Failed to write active environment")?;

    println!(
        "{} Active environment set to {}",
        "ok".green().bold(),
        name.cyan().bold()
    );
    println!(
        "{} New secrets will be stored under the {} namespace.",
        "->".blue().bold(),
        name.cyan()
    );
    Ok(())
}

/// `phantom env list` — list known environments extracted from vault keys.
pub fn run_list() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(config.local_project_id());
    let all_keys = vault.list().context("Failed to list vault keys")?;

    let current = phantom_core::env_scope::read_active_env(&project_dir);
    let envs = known_envs_from_keys(&all_keys, &current);

    println!("{} Known environments:\n", "->".blue().bold());
    for env in &envs {
        if env == &current {
            println!(
                "   {} {} {}",
                "*".green().bold(),
                env.bold(),
                "(active)".dimmed()
            );
        } else {
            println!("   {} {}", "-".dimmed(), env);
        }
    }

    if envs.len() == 1 {
        println!(
            "\n{} Only the default environment exists. Use {} to create more.",
            "->".blue().bold(),
            "phantom env new <name>".cyan()
        );
    }

    Ok(())
}

/// `phantom env new <name>` — declare a new environment (no-op if it already exists).
/// Secrets are added per-key via `phantom add --env <name>`.
pub fn run_new(name: &str) -> Result<()> {
    validate_env_name(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    // Check if env already has any keys in vault
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(config.local_project_id());
    let all_keys = vault.list().context("Failed to list vault keys")?;
    let prefix = format!("{name}/");
    let existing_count = all_keys.iter().filter(|k| k.starts_with(&prefix)).count();

    if existing_count > 0 {
        println!(
            "{} Environment {} already exists ({} secret(s)).",
            "!".yellow().bold(),
            name.cyan().bold(),
            existing_count
        );
    } else {
        println!(
            "{} Environment {} declared.",
            "ok".green().bold(),
            name.cyan().bold()
        );
    }

    println!(
        "{} Add secrets with: {}",
        "->".blue().bold(),
        format!("phantom add --env {name} KEY").cyan()
    );
    println!(
        "{} Switch to it with: {}",
        "->".blue().bold(),
        format!("phantom env use {name}").cyan()
    );

    Ok(())
}

/// `phantom env copy --from <src> --to <dst>` — copy all secrets from one env to another.
pub fn run_copy(from: &str, to: &str) -> Result<()> {
    validate_env_name(from).map_err(|e| anyhow::anyhow!("{e}"))?;
    validate_env_name(to).map_err(|e| anyhow::anyhow!("{e}"))?;

    if from == to {
        anyhow::bail!("--from and --to must be different environments.");
    }

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(config.local_project_id());
    let all_keys = vault.list().context("Failed to list vault keys")?;

    // Find all keys in the source environment.
    // For `default` env, also include bare keys (backward compat).
    let src_keys: Vec<(String, String)> = all_keys
        .iter()
        .filter_map(|k| {
            if let Some((env, name)) = split_key(k) {
                if env == from {
                    return Some((k.clone(), name.to_string()));
                }
            } else if from == DEFAULT_ENV {
                // bare key — belongs to default env
                return Some((k.clone(), k.clone()));
            }
            None
        })
        .collect();

    if src_keys.is_empty() {
        anyhow::bail!(
            "No secrets found in environment '{}'. Add some with: {}",
            from,
            format!("phantom add --env {from} KEY").cyan()
        );
    }

    println!(
        "{} Copying {} secret(s) from {} to {}...\n",
        "->".blue().bold(),
        src_keys.len(),
        from.cyan().bold(),
        to.cyan().bold()
    );

    let mut copied = 0;
    for (vault_key, name) in &src_keys {
        let value = vault
            .retrieve(vault_key)
            .context(format!("Failed to retrieve '{vault_key}'"))?;
        let dst_key = namespaced_key(to, name);
        vault
            .store(&dst_key, value.as_str())
            .context(format!("Failed to store '{dst_key}'"))?;
        println!(
            "   {} {} -> {}/{}",
            "+".green().bold(),
            name.bold(),
            to.cyan(),
            name
        );
        copied += 1;
    }

    println!(
        "\n{} Copied {} secret(s) to environment '{}'.",
        "ok".green().bold(),
        copied,
        to.cyan().bold()
    );
    println!(
        "{} Switch to it with: {}",
        "->".blue().bold(),
        format!("phantom env use {to}").cyan()
    );

    Ok(())
}

/// `phantom env` with no subcommand — show help hint.
pub fn run_default(current: &str) -> Result<()> {
    println!(
        "{} Active environment: {}",
        "->".blue().bold(),
        current.cyan().bold()
    );
    println!(
        "{}",
        "Use a subcommand: use <name> | list | new <name> | copy --from <src> --to <dst>".dimmed()
    );
    println!(
        "  {} — generate .env.example for team onboarding",
        "phantom env example".cyan()
    );
    Ok(())
}

/// Resolve env from flag or persisted file, used by vault call sites.
pub fn effective_env(project_dir: &std::path::Path, flag: Option<&str>) -> String {
    resolve_env(project_dir, flag)
}
