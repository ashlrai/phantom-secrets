use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::dotenv::EnvEntry;
use phantom_core::token::TokenMap;
use std::path::Path;

/// Set up vault, generate tokens, store secrets, and atomically rewrite the .env file.
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

    // Never leave a plaintext project-local backup: AI permission patterns,
    // editor indexing, and accidental archive tooling can all cross .gitignore.
    // The core writer stages privately, fsyncs, and atomically replaces .env.
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
