use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::TokenMap;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Copy a secret from the current project's vault to another project's vault.
pub fn run(name: &str, target_dir: &PathBuf, rename: &Option<String>) -> Result<()> {
    let source_dir = std::env::current_dir()?;
    let source_config_path = source_dir.join(".phantom.toml");

    if !source_config_path.exists() {
        anyhow::bail!(
            "Source project is not initialized.\nRun {} first.",
            "phantom init".cyan().bold()
        );
    }

    let target_dir = if target_dir.is_relative() {
        source_dir.join(target_dir)
    } else {
        target_dir.clone()
    };
    let target_dir = target_dir
        .canonicalize()
        .context("Target directory does not exist")?;
    let target_config_path = target_dir.join(".phantom.toml");

    if !target_config_path.exists() {
        anyhow::bail!(
            "Target project at {} is not initialized.\nRun {} in that directory first.",
            target_dir.display(),
            "phantom init".cyan().bold()
        );
    }

    // Load source vault
    let source_config = PhantomConfig::load(&source_config_path)?;
    let source_vault = phantom_vault::create_vault(&source_config.phantom.project_id);

    // Retrieve the secret
    let mut secret_value = source_vault
        .retrieve(name)
        .context(format!("Secret '{}' not found in source vault", name))?;

    let target_name = rename.as_deref().unwrap_or(name);

    println!(
        "{} Copying {} -> {} in {}",
        "->".blue().bold(),
        name.bold(),
        target_name.bold(),
        target_dir.display()
    );

    // Load target vault
    let target_config = PhantomConfig::load(&target_config_path)?;
    let target_vault = phantom_vault::create_vault(&target_config.phantom.project_id);

    // Store in target vault
    target_vault
        .store(target_name, &secret_value)
        .context("Failed to store secret in target vault")?;

    // Update target .env with a new phantom token
    let target_env_path = target_dir.join(".env");
    if target_env_path.exists() {
        let dotenv = DotenvFile::parse_file(&target_env_path)?;
        let mut token_map = TokenMap::new();
        let token = token_map.insert(target_name.to_string());

        // Check if key already exists in target .env
        let key_exists = dotenv.entries().iter().any(|e| e.key == target_name);

        if key_exists {
            // Rewrite existing entry
            let (content, _) = dotenv.rewrite_with_phantoms(&token_map);
            std::fs::write(&target_env_path, content)?;
        } else {
            // Append new entry
            let mut content = std::fs::read_to_string(&target_env_path)?;
            if !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(&format!("{}={}\n", target_name, token));
            std::fs::write(&target_env_path, content)?;
        }

        println!(
            "   {} Updated {} with phantom token",
            "+".green().bold(),
            ".env".cyan()
        );
    }

    // Zeroize the secret from memory
    secret_value.zeroize();

    println!(
        "\n{} Secret copied successfully (value never printed)",
        "ok".green().bold()
    );

    Ok(())
}
