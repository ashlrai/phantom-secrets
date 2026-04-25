mod config;
mod docs;
mod env;
mod hooks;
mod prompts;
mod vault;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::dotenv::{DotenvFile, SecretClassification};
use std::path::Path;

pub fn run(env_path_arg: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;

    // Auto-detect .env file if the default wasn't found
    let env_path = if Path::new(env_path_arg).exists() {
        std::path::PathBuf::from(env_path_arg)
    } else {
        env::find_env_file(&cwd, env_path_arg).ok_or_else(|| {
            anyhow::anyhow!(
                "No .env file found.\n\
                 Checked: .env, .env.local, .env.development, .env.development.local\n\
                 (also searched immediate subdirectories)\n\n\
                 Create a .env file with your secrets, or specify one:\n\
                 {}",
                "phantom init --from .env.local".cyan().bold()
            )
        })?
    };

    // Config and project dir are based on where the .env file lives (not cwd)
    // Canonicalize for stable project IDs regardless of which directory user runs from
    let project_dir = env_path.parent().unwrap_or(&cwd).to_path_buf();
    let project_dir = project_dir
        .canonicalize()
        .unwrap_or_else(|_| cwd.join(&project_dir));
    let config_path = project_dir.join(".phantom.toml");

    // Parse .env file
    println!("{} Reading {}...", "->".blue().bold(), env_path.display());
    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env file")?;

    // Classify all entries
    let classified = dotenv.classified_entries();
    let real_entries: Vec<_> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::Secret)
        .map(|(e, _)| *e)
        .collect();
    let public_entries: Vec<_> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::PublicKey)
        .map(|(e, _)| *e)
        .collect();

    if real_entries.is_empty() {
        println!(
            "{} No real secrets found in {} (all values are already phantom tokens, public keys, or config)",
            "!".yellow().bold(),
            env_path.display()
        );
        if !public_entries.is_empty() {
            println!(
                "\n{} {} public key(s) detected (safe for browser bundles, not protected):",
                "->".blue().bold(),
                public_entries.len()
            );
            for entry in &public_entries {
                println!("   {} {}", "·".dimmed(), entry.key);
            }
        }
        return Ok(());
    }

    println!(
        "{} Found {} secret(s) to protect:",
        "->".blue().bold(),
        real_entries.len()
    );
    for entry in &real_entries {
        println!("   {} {}", "+".cyan().bold(), entry.key.bold());
    }

    if !public_entries.is_empty() {
        println!(
            "\n{} Skipping {} public key(s) (safe for browser bundles):",
            "->".blue().bold(),
            public_entries.len()
        );
        for entry in &public_entries {
            println!("   {} {}", "·".dimmed(), entry.key);
        }
        println!("   Override with: {}", "phantom add --force <KEY>".dimmed());
    }

    // Load or create config, then auto-detect services
    let mut phantom_config = config::load_or_create(&project_dir, &config_path)?;
    config::apply_detected_services(&mut phantom_config, &real_entries);

    // Set up vault, store secrets, backup and rewrite .env
    vault::setup_and_store(
        &real_entries,
        &phantom_config.phantom.project_id,
        &env_path,
        &dotenv,
    )?;

    // Persist public key classifications
    if !public_entries.is_empty() {
        phantom_config.public_keys = public_entries.iter().map(|e| e.key.clone()).collect();
    }

    // Save config
    phantom_config.save(&config_path)?;
    println!("{} Saved .phantom.toml", "ok".green().bold());

    // Add .phantom.toml to .gitignore if needed
    env::ensure_gitignore(&project_dir)?;

    // Generate .env.example for team onboarding
    let example_path = project_dir.join(".env.example");
    let example_content = dotenv.generate_example_content(Some(&phantom_config));
    std::fs::write(&example_path, &example_content)?;
    println!(
        "{} Generated {} (commit this for team onboarding)",
        "ok".green().bold(),
        ".env.example".cyan()
    );

    // Install pre-commit hook if in a git repo
    hooks::install_precommit_hook(&project_dir);

    println!(
        "\n{} {} secret(s) are now protected!",
        "done".green().bold(),
        real_entries.len()
    );

    // Auto-configure Claude Code if detected (merges phantom setup into init)
    // Check project_dir first, fall back to cwd (repo root) for monorepos
    prompts::auto_setup_claude_code(&project_dir, &cwd);

    // Add Phantom instructions to CLAUDE.md so Claude knows how to use it
    docs::auto_add_claude_md(&project_dir, &cwd);

    // Add development setup section to README.md
    docs::auto_add_readme(&project_dir, &cwd);

    // Detect deployment platforms and suggest sync setup
    prompts::detect_platforms(&project_dir, &cwd);

    println!(
        "\n{} Run {} to start coding with AI safely.",
        "next".blue().bold(),
        "phantom exec -- <your-command>".cyan().bold()
    );

    Ok(())
}
