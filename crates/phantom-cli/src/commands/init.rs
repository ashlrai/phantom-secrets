use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::TokenMap;
use std::path::Path;

pub fn run(env_path: &str) -> Result<()> {
    let env_path = Path::new(env_path);
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    // Parse .env file
    println!("{} Reading {}...", "->".blue().bold(), env_path.display());
    let dotenv = DotenvFile::parse_file(env_path).context("Failed to read .env file")?;

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
    let config = if config_path.exists() {
        println!("{} Loading existing .phantom.toml", "->".blue().bold());
        PhantomConfig::load(&config_path)?
    } else {
        PhantomConfig::new_with_defaults(project_id.clone())
    };

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

    // Rewrite .env with phantom tokens
    let _originals = dotenv
        .write_phantomized(&token_map, env_path)
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
    println!(
        "\n{} Run {} to start coding with AI safely.",
        "next".blue().bold(),
        "phantom exec -- <your-command>".cyan().bold()
    );

    Ok(())
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
    for pattern in &[".env", ".env.local", ".env.*.local"] {
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
