use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;

/// Generate a .env.example file from the current .env.
/// Secret values are replaced with descriptive placeholders.
/// Non-secret values and public keys are preserved as-is.
pub fn run(output: &str) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let config = PhantomConfig::load(&config_path).ok();
    let env_path = match config.as_ref() {
        Some(config) => {
            phantom_core::managed_dotenv::resolve_dotenv(&project_dir, config, &[])?.path
        }
        None => project_dir.join(".env"),
    };
    let output_path = project_dir.join(output);

    if !env_path.exists() {
        anyhow::bail!(
            "No .env file found in current directory.\n  {}",
            crate::util::docs_url("getting-started")
        );
    }

    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env")?;
    let entries = dotenv.entries();

    if entries.is_empty() {
        println!("{} .env is empty.", "!".yellow().bold());
        return Ok(());
    }

    // Load config for service info if available
    // Use shared generation logic from phantom-core
    let content = dotenv.generate_example_content(config.as_ref());
    std::fs::write(&output_path, &content)?;

    let secret_count =
        dotenv.real_secret_entries().len() + entries.iter().filter(|e| e.is_phantom).count();
    let config_count = entries.len() - secret_count;

    println!(
        "{} Generated {} ({} secrets masked, {} config values preserved)",
        "ok".green().bold(),
        output.cyan(),
        secret_count,
        config_count
    );
    println!(
        "{} Share this file with your team for onboarding.",
        "->".blue().bold()
    );

    Ok(())
}
