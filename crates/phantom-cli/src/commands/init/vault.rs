use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::dotenv::EnvEntry;
use phantom_core::token::TokenMap;
use std::path::Path;

/// Set up vault, generate tokens, store secrets, backup and rewrite the .env file.
/// Returns the token map (phantom token -> real value mappings).
pub fn setup_and_store(
    real_entries: &[&EnvEntry],
    project_id: &str,
    env_path: &Path,
    dotenv: &phantom_core::dotenv::DotenvFile,
) -> Result<TokenMap> {
    let vault = phantom_vault::create_vault(project_id);
    println!(
        "{} Using {} vault backend",
        "->".blue().bold(),
        vault.backend_name().cyan()
    );

    // Generate phantom tokens and store real secrets
    let mut token_map = TokenMap::new();
    for entry in real_entries {
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
    std::fs::copy(env_path, &backup_path).context("Failed to create .env backup")?;
    println!(
        "   {} Backed up original .env to {}",
        "+".green().bold(),
        backup_path.display()
    );

    // Rewrite .env with phantom tokens
    dotenv
        .write_phantomized(&token_map, env_path)
        .context("Failed to rewrite .env file")?;

    println!(
        "\n{} Rewrote {} with phantom tokens",
        "ok".green().bold(),
        env_path.display()
    );

    Ok(token_map)
}
